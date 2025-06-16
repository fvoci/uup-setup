# -*- coding: utf-8 -*-
"""
UUP Dump에서 최신 Windows 11 정식 빌드를 자동으로 찾아 다운로드하고,
ISO 변환을 위한 고급 설정을 적용하여 스크립트 패키지를 수정한 뒤,
CI/CD 환경을 위해 릴리스 정보를 JSON 파일로 생성하는 스크립트.

이 스크립트는 다음 워크플로우를 따릅니다:
1. UUP Dump에서 최신 빌드의 스크립트 패키지(.zip)를 다운로드합니다.
2. 원본 스크립트 패키지의 압축을 메모리에서 해제합니다.
3. 'ConvertConfig.ini'를 설정한 옵션에 맞게 수정합니다.
4. 수정된 구성을 포함하여 새로운 .zip 파일을 생성합니다.
5. 최종적으로 생성된 .zip 파일의 정보와 빌드 정보를 JSON 파일로 출력합니다.
"""

import argparse
import configparser
import io
import json
import logging
import os
import re
import sys
import time
import zipfile
from dataclasses import dataclass, field, fields
from itertools import groupby
from pathlib import Path
from typing import Any, Dict, List, Tuple

import cloudscraper
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class ConversionOptions:
	"""
	ISO 변환 스크립트(ConvertConfig.ini)를 위한 고급 설정값.
	모든 옵션은 기본적으로 활성화(True)되며, --no-<기능명> 플래그로 비활성화할 수 있습니다.
	"""

	add_updates: bool = True
	cleanup: bool = True
	reset_base: bool = True
	update_boot_files: bool = True
	force_dism: bool = True
	integrate_dotnet: bool = True
	integrate_winre_updates: bool = True
	create_esd: bool = False  # ESD 생성은 기본적으로 비활성화

	_INI_KEY_MAP = {
		'add_updates': 'AddUpdates',
		'cleanup': 'Cleanup',
		'reset_base': 'ResetBase',
		'update_boot_files': 'UpdtBootFiles',
		'force_dism': 'ForceDism',
		'integrate_dotnet': 'NetFx3',
		'integrate_winre_updates': 'LCUwinre',
		'create_esd': 'wim2esd',
	}

	def to_ini_dict(self) -> Dict[str, str]:
		"""클래스 필드를 동적으로 읽어 ConvertConfig.ini에 쓸 딕셔너리를 생성합니다."""
		ini_dict = {}
		for attr_name, ini_key in self._INI_KEY_MAP.items():
			value = getattr(self, attr_name)
			if isinstance(value, bool):
				ini_dict[ini_key] = '1' if value else '0'
		return ini_dict


@dataclass
class DownloaderConfig:
	"""스크립트 실행을 위한 전체 설정값을 저장하는 데이터 클래스."""

	language: str = 'ko-kr'
	editions: List[str] = field(
		default_factory=lambda: ['CORE', 'PROFESSIONAL']
	)
	arch: str = 'all'
	include_virtual_editions: bool = True
	output_json_path: str = 'release_info.json'
	conversion_options: ConversionOptions = field(
		default_factory=ConversionOptions
	)


@dataclass
class DownloadSpec:
	"""개별 빌드 다운로드를 위한 명세를 저장하는 데이터 클래스."""

	build_info: Dict[str, Any]
	config: DownloaderConfig
	base_editions: List[str]
	virtual_editions: List[str] = field(default_factory=list)

	@property
	def update_id(self) -> str:
		return self.build_info.get('uuid', '')

	@property
	def language(self) -> str:
		return self.config.language


class UUPDumpDownloader:
	"""UUP Dump에서 Windows 빌드 스크립트를 다운로드하고 수정하는 클래스."""

	BASE_API_URL = 'https://api.uupdump.net'
	BASE_WEB_URL = 'https://uupdump.net'
	GET_PHP_URL = f'{BASE_WEB_URL}/get.php'
	DOWNLOAD_PHP_URL = f'{BASE_WEB_URL}/download.php'
	HTTP_HEADERS = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
	}

	def __init__(self, config: DownloaderConfig):
		self.config = config
		self.scraper = cloudscraper.create_scraper()
		logger.info(
			f'다운로더 초기화 완료. 적용될 INI 설정: {config.conversion_options.to_ini_dict()}'
		)

	def run(self) -> Dict[str, Any]:
		"""전체 다운로드 및 수정 프로세스를 실행하고 릴리스 정보를 반환합니다."""
		logger.info('UUP Dump 다운로드 및 스크립트 수정 프로세스를 시작합니다.')
		latest_builds = self.fetch_latest_builds()
		if not latest_builds:
			raise RuntimeError('다운로드할 최신 빌드를 찾지 못했습니다.')

		release_artifacts = []
		for i, build in enumerate(latest_builds):
			arch, title = build.get('arch'), build.get('title', 'Unknown Build')
			if not arch:
				logger.warning(
					f"빌드 '{title}'에 아키텍처 정보가 없어 건너뜁니다."
				)
				continue

			try:
				logger.info(f'--- [{arch}] 처리 시작: {title} ---')
				spec = self._create_download_spec(build)
				virtual_editions = self._fetch_virtual_editions(spec)
				final_spec = DownloadSpec(
					build_info=spec.build_info,
					config=spec.config,
					base_editions=spec.base_editions,
					virtual_editions=virtual_editions,
				)
				artifact_info = self._create_modified_package(final_spec)
				release_artifacts.append(artifact_info)
				logger.info(f'--- [{arch}] 처리 완료: {title} ---')
			except Exception as e:
				logger.error(
					f'빌드 {title} 처리 중 오류 발생: {e}',
					exc_info=logger.isEnabledFor(logging.DEBUG),
				)
				continue

			if i < len(latest_builds) - 1:
				logger.info('다음 아키텍처 처리 전 5초간 대기합니다...')
				time.sleep(5)

		common_build_info = self._extract_common_build_info(release_artifacts)
		return {**common_build_info, 'artifacts': release_artifacts}

	def fetch_latest_builds(self) -> List[Dict[str, Any]]:
		"""UUP Dump에서 가장 최신 버전의 정식 Windows 11 빌드를 아키텍처별로 가져옵니다."""
		logger.info('1/4: 최신 Windows 11 빌드 정보 수집 중...')
		arch_map = {
			'amd64': ['Windows 11, version amd64'],
			'arm64': ['Windows 11, version arm64'],
			'all': ['Windows 11, version amd64', 'Windows 11, version arm64'],
		}
		search_terms = arch_map.get(self.config.arch, [])
		if not search_terms:
			raise ValueError(f'지원하지 않는 아키텍처: {self.config.arch}')

		all_builds = []
		for term in search_terms:
			response_data = self._make_api_request(
				'/listid.php', {'search': term, 'sortByDate': '1'}
			)
			all_builds.extend(response_data.get('builds', {}).values())

		release_builds = [
			b
			for b in all_builds
			if 'windows 11, version' in b.get('title', '').lower()
			and 'cumulative' not in b.get('title', '').lower()
		]
		if not release_builds:
			return []

		release_builds.sort(
			key=lambda b: (
				b.get('arch', ''),
				self._extract_version_key(b.get('title', '')),
				b.get('created', 0),
			),
			reverse=True,
		)
		latest_builds = [
			next(group)
			for _, group in groupby(release_builds, key=lambda b: b.get('arch'))
		]
		for build in latest_builds:
			logger.info(
				f'최신 빌드 발견: {build.get("title")} (Arch: {build.get("arch")}, UUID: {build.get("uuid")})'
			)
		return latest_builds

	def _create_download_spec(self, build_info: Dict[str, Any]) -> DownloadSpec:
		"""선택한 언어와 에디션의 유효성을 검증하고 다운로드 명세를 생성합니다."""
		logger.info('2/4: 언어 및 에디션 유효성 검증 중...')
		update_id = build_info['uuid']
		target_lang = self.config.language
		available_langs = self._make_api_request(
			'/listlangs.php', {'id': update_id}
		).get('langList', [])
		if target_lang not in available_langs:
			raise ValueError(
				f"언어 '{target_lang}'가 지원되지 않습니다. (빌드: {build_info.get('title')})"
			)
		logger.info(f'언어 확인: {target_lang}')

		available_editions = self._make_api_request(
			'/listeditions.php', {'id': update_id, 'lang': target_lang}
		).get('editionList', [])
		validated_editions = [
			e for e in self.config.editions if e in available_editions
		]
		if not validated_editions:
			raise ValueError(
				f'요청한 에디션 {self.config.editions} 중 사용 가능한 것이 없습니다. (빌드: {build_info.get("title")})'
			)
		logger.info(f'에디션 확인: {validated_editions}')
		return DownloadSpec(
			build_info=build_info,
			config=self.config,
			base_editions=validated_editions,
		)

	def _fetch_virtual_editions(self, spec: DownloadSpec) -> List[str]:
		"""웹 페이지를 파싱하여 사용 가능한 가상 에디션 목록을 가져옵니다."""
		if not self.config.include_virtual_editions:
			logger.info('3/4: 가상 에디션 수집 건너뜀.')
			return []

		logger.info('3/4: 가상 에디션 정보 수집 중...')
		editions_str = ';'.join(spec.base_editions)
		page_url = f'{self.DOWNLOAD_PHP_URL}?id={spec.update_id}&pack={spec.language}&edition={editions_str}'
		try:
			resp = self.scraper.get(
				page_url, headers=self.HTTP_HEADERS, timeout=30
			)
			resp.raise_for_status()
			soup = BeautifulSoup(resp.text, 'lxml')
			inputs = soup.select('input[name="virtualEditions[]"]')
			found_editions = [i['value'] for i in inputs]
			logger.info(f'발견된 가상 에디션: {found_editions}')
			return found_editions
		except Exception as e:
			logger.warning(
				f'가상 에디션 수집 실패: {e}. 가상 에디션 없이 진행합니다.'
			)
			return []

	def _create_modified_package(self, spec: DownloadSpec) -> Dict[str, Any]:
		"""스크립트 패키지를 다운로드하고, INI 수정 후, 새 ZIP으로 저장합니다."""
		logger.info('4/4: 원본 스크립트 패키지 다운로드 및 수정 중...')
		original_zip_content, original_filename = (
			self._download_original_package(spec)
		)

		modified_zip_path = self._modify_zip_package(
			original_zip_content,
			original_filename,
			spec.config.conversion_options,
		)
		file_size_mb = modified_zip_path.stat().st_size / (1024 * 1024)
		logger.info(
			f'수정된 패키지 생성 완료: {modified_zip_path} ({file_size_mb:.2f} MB)'
		)
		return {
			'arch': spec.build_info.get('arch'),
			'uuid': spec.update_id,
			'title': spec.build_info.get('title'),
			'filename': str(modified_zip_path),
			'size_mb': round(file_size_mb, 4),
			'editions': {
				'base': spec.base_editions,
				'virtual': spec.virtual_editions,
			},
			'conversion_options': spec.config.conversion_options.to_ini_dict(),
		}

	def _download_original_package(
		self, spec: DownloadSpec
	) -> Tuple[bytes, str]:
		"""서버에서 생성된 원본 ZIP 패키지를 메모리로 다운로드합니다."""
		editions_str = ';'.join(spec.base_editions)
		url = f'{self.GET_PHP_URL}?id={spec.update_id}&pack={spec.language}&edition={editions_str}'
		conv_opts = spec.config.conversion_options

		post_data_map = {
			'add_updates': 'updates',
			'cleanup': 'cleanup',
			'integrate_dotnet': 'dotnet',
			'create_esd': 'esd',
		}
		post_data = {'uefi': '1'}
		for attr, key in post_data_map.items():
			if getattr(conv_opts, attr):
				post_data[key] = '1'

		if spec.config.include_virtual_editions and spec.virtual_editions:
			post_data['autodl'] = '3'
			post_data['virtualEditions[]'] = spec.virtual_editions
		else:
			post_data['autodl'] = '2'

		try:
			resp = self.scraper.post(
				url, data=post_data, headers=self.HTTP_HEADERS, timeout=60
			)
			resp.raise_for_status()
			content_disp = resp.headers.get('Content-Disposition', '')
			match = re.search(r'filename="(.+?\.zip)"', content_disp)
			if not match:
				raise RuntimeError(
					f'응답에서 유효한 ZIP 파일명을 찾을 수 없습니다: {resp.text[:200]}'
				)
			filename = Path(match.group(1)).name
			logger.info(f'원본 패키지 다운로드 완료: {filename}')
			return resp.content, filename
		except requests.exceptions.RequestException as e:
			raise RuntimeError(f'원본 패키지 다운로드 실패: {e}') from e

	def _modify_zip_package(
		self,
		zip_content: bytes,
		original_filename: str,
		conv_options: ConversionOptions,
	) -> Path:
		"""메모리에 있는 ZIP 파일의 내용을 수정하고 새 ZIP 파일로 저장합니다."""
		output_filename = Path(original_filename)
		ini_path = 'ConvertConfig.ini'
		try:
			with (
				io.BytesIO(zip_content) as bio,
				zipfile.ZipFile(bio, 'r') as zin,
				zipfile.ZipFile(
					output_filename, 'w', compression=zipfile.ZIP_DEFLATED
				) as zout,
			):
				config = configparser.ConfigParser()
				if ini_path in zin.namelist():
					config.read_string(zin.read(ini_path).decode('utf-8'))

				logger.info(f"'{ini_path}' 수정 중...")
				if not config.has_section('convert-UUP'):
					config.add_section('convert-UUP')

				for key, value in conv_options.to_ini_dict().items():
					logger.debug(f'   - INI 설정 강제: {key} = {value}')
					config.set('convert-UUP', key, value)

				string_writer = io.StringIO()
				config.write(string_writer)
				zout.writestr(
					ini_path, string_writer.getvalue().encode('utf-8')
				)

				for item in zin.infolist():
					if item.filename != ini_path:
						zout.writestr(item, zin.read(item.filename))
		except Exception as e:
			raise RuntimeError(f'ZIP 패키지 수정 중 오류 발생: {e}') from e
		return output_filename

	def _make_api_request(self, endpoint: str, params: dict) -> Dict[str, Any]:
		"""UUP Dump API에 요청을 보내고 JSON 응답을 반환합니다."""
		try:
			url = f'{self.BASE_API_URL}{endpoint}'
			response = self.scraper.get(
				url, params=params, headers=self.HTTP_HEADERS, timeout=30
			)
			logger.debug(f'API 요청: GET {response.url}')
			response.raise_for_status()
			json_data = response.json()
			if error := json_data.get('error'):
				raise RuntimeError(f'API 오류: {error}')
			return json_data.get('response', {})
		except requests.exceptions.RequestException as e:
			raise RuntimeError(f'API 요청 실패: {endpoint} ({e})') from e

	def _extract_common_build_info(
		self, artifacts: List[Dict[str, Any]]
	) -> Dict[str, str]:
		"""처리된 아티팩트 목록에서 공통 빌드 정보를 추출합니다."""
		if not artifacts:
			return {}
		title = artifacts[0].get('title', '')
		version_match = re.search(r'\((\d+\.\d+)\)', title)
		name_match = re.search(r'version (\d+H\d)', title, re.IGNORECASE)
		return {
			'build_version': version_match.group(1) if version_match else 'N/A',
			'build_name': name_match.group(1).upper() if name_match else 'N/A',
			'language': self.config.language,
		}

	@staticmethod
	def _extract_version_key(title: str) -> Tuple[int, int]:
		"""빌드 제목에서 '24H2'와 같은 버전 정보를 추출하여 정렬 가능한 키로 반환합니다."""
		if match := re.search(r'version (\d{2})H(\d)', title, re.IGNORECASE):
			return int(match.group(1)), int(match.group(2))
		return 0, 0


def setup_logging(debug: bool) -> None:
	"""로깅 설정을 초기화합니다."""
	log_level = logging.DEBUG if debug else logging.INFO
	is_ci_env = os.environ.get('CI')
	log_format = (
		'[%(levelname)s] %(message)s'
		if is_ci_env
		else '[%(asctime)s] [%(levelname)s] %(message)s'
	)
	date_format = None if is_ci_env else '%Y-%m-%d %H:%M:%S'
	logging.basicConfig(
		level=log_level,
		format=log_format,
		datefmt=date_format,
		stream=sys.stdout,
	)


def main() -> None:
	"""스크립트의 메인 진입점입니다."""
	parser = argparse.ArgumentParser(
		description='UUP Dump에서 스크립트를 다운로드하고 고급 설정을 적용하여 재압축합니다.',
		formatter_class=argparse.ArgumentDefaultsHelpFormatter,
	)

	base_group = parser.add_argument_group('Base Download Options')
	base_group.add_argument(
		'--language',
		'-l',
		type=str,
		default='ko-kr',
		help='다운로드할 언어 코드',
	)
	base_group.add_argument(
		'--editions',
		'-e',
		nargs='+',
		default=['CORE', 'PROFESSIONAL'],
		help='다운로드할 기본 에디션 목록',
	)
	base_group.add_argument(
		'--arch',
		choices=['amd64', 'arm64', 'all'],
		default='all',
		help='대상 아키텍처',
	)
	base_group.add_argument(
		'--no-virtual-editions',
		dest='include_virtual_editions',
		action='store_false',
		help='가상 에디션을 포함하지 않음',
	)

	conv_group = parser.add_argument_group('Conversion Options')

	opt_out_arguments = [
		('no-updates', 'add_updates', '누적 업데이트를 통합하지 않음'),
		('no-cleanup', 'cleanup', '대체된 구성 요소 정리 안 함'),
		('no-dotnet', 'integrate_dotnet', '.NET Framework 3.5를 통합하지 않음'),
		('no-reset-base', 'reset_base', '통합 후 이미지 기반을 리셋하지 않음'),
		(
			'no-update-boot-files',
			'update_boot_files',
			'ISO 부팅 파일을 업데이트하지 않음',
		),
		(
			'no-integrate-winre-updates',
			'integrate_winre_updates',
			'WinRE(복구 환경)를 업데이트하지 않음',
		),
		(
			'no-force-dism',
			'force_dism',
			'wimlib 대신 시스템 DISM 사용을 강제하지 않음',
		),
	]

	opt_in_arguments = [
		(
			'create-esd',
			'create_esd',
			'WIM 대신 압축률이 높은 ESD 파일을 생성 (기본: WIM)',
		),
	]

	for flag, dest, help_text in opt_out_arguments:
		conv_group.add_argument(
			f'--{flag}', dest=dest, action='store_false', help=help_text
		)

	for flag, dest, help_text in opt_in_arguments:
		conv_group.add_argument(
			f'--{flag}', dest=dest, action='store_true', help=help_text
		)

	run_group = parser.add_argument_group('Script Execution Options')
	run_group.add_argument(
		'--debug', action='store_true', help='상세한 디버그 로그를 출력'
	)
	run_group.add_argument(
		'--output-json',
		type=str,
		default='release_info.json',
		help='릴리스 정보 JSON 파일 출력 경로',
	)
	run_group.add_argument(
		'--force-json-output',
		action='store_true',
		help='CI 환경이 아니더라도 JSON 파일 생성을 강제함',
	)

	args = parser.parse_args()
	setup_logging(args.debug)

	try:
		conv_opts_kwargs = {
			field.name: getattr(args, field.name)
			for field in fields(ConversionOptions)
		}
		conv_options = ConversionOptions(**conv_opts_kwargs)

		config = DownloaderConfig(
			language=args.language,
			editions=args.editions,
			arch=args.arch,
			include_virtual_editions=args.include_virtual_editions,
			output_json_path=args.output_json,
			conversion_options=conv_options,
		)
		downloader = UUPDumpDownloader(config)
		release_info = downloader.run()

		is_ci_env = os.environ.get('CI')
		if is_ci_env or args.force_json_output:
			if release_info.get('artifacts'):
				with open(
					Path(config.output_json_path), 'w', encoding='utf-8'
				) as f:
					json.dump(release_info, f, ensure_ascii=False, indent=2)
				logger.info(
					f"릴리스 정보가 '{config.output_json_path}' 파일에 저장되었습니다."
				)
			else:
				logger.warning(
					'처리된 아티팩트가 없어 릴리스 정보 파일을 생성하지 않았습니다.'
				)
		else:
			logger.info(
				'CI 환경이 아니므로 릴리스 정보 파일을 생성하지 않습니다. (생성을 원하면 --force-json-output 사용)'
			)

	except Exception as e:
		logger.error(f'스크립트 실행 중 심각한 오류가 발생했습니다: {e}')
		if args.debug:
			logger.exception('예외 상세 정보:')
		sys.exit(1)

	logger.info('모든 작업이 성공적으로 완료되었습니다.')


if __name__ == '__main__':
	main()
