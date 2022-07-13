# region Analyze SDK - _util.py
import warnings


def deprecated(message: str):
    def wrapper(func):
        warnings.warn(message,
                      DeprecationWarning,
                      stacklevel=2)
        return func

    return wrapper


# endregion

# region consts.py

from enum import Enum
from enum import IntEnum


class AnalysisStatusCode(Enum):
    CREATED = 'created'
    IN_PROGRESS = 'in_progress'
    QUEUED = 'queued'
    FAILED = 'failed'
    FINISH = 'finished'


class IndexStatusCode(Enum):
    CREATED = 'created'
    IN_PROGRESS = 'in_progress'
    FINISH = 'finished'


class IndexType(Enum):
    TRUSTED = 'trusted'
    MALICIOUS = 'malicious'

    @staticmethod
    def from_str(label):
        if label in ('TRUSTED', 'trusted'):
            return IndexType.TRUSTED
        elif label in ('MALICIOUS', 'malicious'):
            return IndexType.MALICIOUS
        else:
            raise NotImplementedError


class CodeItemType(Enum):
    FILE = 'file'
    MEMORY_MODULE = 'memory_module'


class OnPremiseVersion(IntEnum):
    V21_11 = 21.11


ANALYZE_URL = 'https://analyze.intezer.com'
BASE_URL = '{}/api/'.format(ANALYZE_URL)
API_VERSION = 'v2-0'
USER_AGENT = 'intezer-python-sdk-{}'.format('1.8.2/anomali')
CHECK_STATUS_INTERVAL = 1

# endregion

# region errors.py

import requests


def _parse_erroneous_response(response: requests.Response):
    try:
        data = response.json()
        return data.get('error', '')
    except ValueError:
        return ''


class IntezerError(Exception):
    pass


class UnsupportedOnPremiseVersion(IntezerError):
    pass


class ServerError(IntezerError):
    def __init__(self, message: str, response: requests.Response):
        self.response = response
        detailed_error = _parse_erroneous_response(response)
        if detailed_error:
            message = '{}. Error:{}'.format(message, detailed_error)
        super().__init__(message)


class AnalysisHasAlreadyBeenSent(IntezerError):
    def __init__(self):
        super(AnalysisHasAlreadyBeenSent, self).__init__('Analysis already been sent')


class IndexHasAlreadyBeenSent(IntezerError):
    def __init__(self):
        super().__init__('Index already been sent')


class FamilyNotFoundError(IntezerError):
    def __init__(self, family_id: str):
        super().__init__('Family not found: {}'.format(family_id))


class HashDoesNotExistError(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Hash was not found', response)


class ReportDoesNotExistError(IntezerError):
    def __init__(self):
        super().__init__('Report was not found')


class AnalysisIsAlreadyRunning(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Analysis already running', response)


class InsufficientQuota(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Insufficient quota', response)


class GlobalApiIsNotInitialized(IntezerError):
    def __init__(self):
        super().__init__('Global API is not initialized')


class AnalysisIsStillRunning(IntezerError):
    def __init__(self):
        super().__init__('Analysis is still running')


class AnalysisFailedError(IntezerError):
    def __init__(self):
        super().__init__('Analysis failed')


class InvalidApiKey(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Invalid api key', response)


class IndexFailed(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Index operation failed', response)


class SubAnalysisOperationStillRunning(IntezerError):
    def __init__(self, operation):
        super(SubAnalysisOperationStillRunning, self).__init__('{} is still running'.format(operation))


# endregion

# region api.py

import typing
from http import HTTPStatus
from typing import Optional

import requests.adapters
from requests import Response

_global_api: typing.Optional['IntezerApi'] = None


def raise_for_status(response: requests.Response,
                     statuses_to_ignore: typing.List[typing.Union[HTTPStatus, int]] = None,
                     allowed_statuses: typing.List[typing.Union[HTTPStatus, int]] = None):
    """Raises stored :class:`HTTPError`, if one occurred."""

    http_error_msg = ''
    if isinstance(response.reason, bytes):
        reason = response.reason.decode('utf-8', 'ignore')
    else:
        reason = response.reason

    if statuses_to_ignore and response.status_code in statuses_to_ignore:
        return
    elif allowed_statuses and response.status_code not in allowed_statuses:
        http_error_msg = '%s Custom Error: %s for url: %s' % (response.status_code, reason, response.url)
    elif 400 <= response.status_code < 500:
        if response.status_code != 400:
            http_error_msg = '%s Client Error: %s for url: %s' % (response.status_code, reason, response.url)
        else:
            # noinspection PyBroadException
            try:
                error = response.json()
                http_error_msg = '\n'.join(['{}:{}.'.format(key, value) for key, value in error['message'].items()])
            except Exception:
                http_error_msg = '%s Client Error: %s for url: %s' % (response.status_code, reason, response.url)
    elif 500 <= response.status_code < 600:
        http_error_msg = '%s Server Error: %s for url: %s' % (response.status_code, reason, response.url)

    if http_error_msg:
        # noinspection PyBroadException
        try:
            data = response.json()
            http_error_msg = '%s, server returns %s, details: %s' % (http_error_msg, data['error'], data.get('details'))
        except Exception:
            pass

        raise requests.HTTPError(http_error_msg, response=response)


class IntezerApi:
    def __init__(self,
                 api_version: str = None,
                 api_key: str = None,
                 base_url: str = None,
                 verify_ssl: bool = True,
                 on_premise_version: OnPremiseVersion = None):
        self.full_url = base_url + api_version
        self.api_key = api_key
        self._access_token = None
        self._session = None
        self._verify_ssl = verify_ssl
        self.on_premise_version = on_premise_version

    def _request(self,
                 method: str,
                 path: str,
                 data: dict = None,
                 headers: dict = None,
                 files: dict = None) -> Response:
        if not self._session:
            self.set_session()

        if files:
            response = self._session.request(
                method,
                self.full_url + path,
                files=files,
                data=data or {},
                headers=headers or {}
            )
        else:
            response = self._session.request(
                method,
                self.full_url + path,
                json=data or {},
                headers=headers
            )

        return response

    def request_with_refresh_expired_access_token(self,
                                                  method: str,
                                                  path: str,
                                                  data: dict = None,
                                                  headers: dict = None,
                                                  files: dict = None) -> Response:
        response = self._request(method, path, data, headers, files)

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            self._access_token = None
            self.set_session()
            response = self._request(method, path, data, headers, files)

        return response

    def analyze_by_hash(self,
                        file_hash: str,
                        disable_dynamic_unpacking: Optional[bool],
                        disable_static_unpacking: Optional[bool],
                        **additional_parameters) -> str:
        data = self._param_initialize(disable_dynamic_unpacking, disable_static_unpacking, **additional_parameters)

        data['hash'] = file_hash
        response = self.request_with_refresh_expired_access_token(path='/analyze-by-hash', data=data, method='POST')
        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def _analyze_file_stream(self, file_stream: typing.BinaryIO, file_name: str, options: dict) -> str:
        file = {'file': (file_name, file_stream)}

        response = self.request_with_refresh_expired_access_token(path='/analyze',
                                                                  files=file,
                                                                  data=options,
                                                                  method='POST')

        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def analyze_by_file(self,
                        file_path: str = None,
                        file_stream: typing.BinaryIO = None,
                        disable_dynamic_unpacking: bool = None,
                        disable_static_unpacking: bool = None,
                        file_name: str = None,
                        code_item_type: str = None,
                        zip_password: str = None,
                        **additional_parameters) -> typing.Optional[str]:
        options = self._param_initialize(disable_dynamic_unpacking,
                                         disable_static_unpacking,
                                         code_item_type,
                                         zip_password,
                                         **additional_parameters)

        if file_stream:
            return self._analyze_file_stream(file_stream, file_name, options)

        with open(file_path, 'rb') as file_to_upload:
            return self._analyze_file_stream(file_to_upload, file_name, options)

    def get_latest_analysis(self,
                            file_hash: str,
                            private_only: bool = False,
                            **additional_parameters) -> typing.Optional[dict]:

        if not self.on_premise_version or self.on_premise_version > OnPremiseVersion.V21_11:
            options = {'should_get_only_private_analysis': private_only, **additional_parameters}
        else:
            options = {}

        response = self.request_with_refresh_expired_access_token(path='/files/{}'.format(file_hash),
                                                                  method='GET',
                                                                  data=options)

        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response)

        return response.json()['result']

    def get_file_analysis_response(self, analyses_id: str, ignore_not_found: bool) -> Response:
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}'.format(analyses_id),
                                                                  method='GET')
        self._assert_result_response(ignore_not_found, response)

        return response

    @deprecated('This method is deprecated, use get_file_analysis_response instead to be explict')
    def get_analysis_response(self, analyses_id: str) -> Response:
        return self.get_file_analysis_response(analyses_id, False)

    def get_url_analysis_response(self, analyses_id: str, ignore_not_found: bool) -> Response:
        response = self.request_with_refresh_expired_access_token(path='/url/{}'.format(analyses_id),
                                                                  method='GET')
        self._assert_result_response(ignore_not_found, response)

        return response

    def get_iocs(self, analyses_id: str) -> typing.Optional[dict]:
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}/iocs'.format(analyses_id),
                                                                  method='GET')
        raise_for_status(response)

        return response.json()['result']

    def get_dynamic_ttps(self, analyses_id: str) -> typing.Optional[dict]:
        self.assert_on_premise_above_v21_11()
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}/dynamic-ttps'.format(analyses_id),
                                                                  method='GET')
        raise_for_status(response)

        return response.json()['result']

    def get_family_info(self, family_id: str) -> typing.Optional[dict]:
        response = self.request_with_refresh_expired_access_token('GET', '/families/{}/info'.format(family_id))
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response, allowed_statuses=[HTTPStatus.OK])
        return response.json()['result']

    def get_family_by_name(self, family_name: str) -> typing.Optional[typing.Dict[str, typing.Any]]:
        response = self.request_with_refresh_expired_access_token('GET', '/families', {'family_name': family_name})
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response, allowed_statuses=[HTTPStatus.OK])
        return response.json()['result']

    def get_sub_analyses_by_id(self, analysis_id: str) -> typing.Optional[list]:
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}/sub-analyses'.format(analysis_id),
                                                                  method='GET')
        raise_for_status(response)

        return response.json()['sub_analyses']

    def get_sub_analysis_code_reuse_by_id(self,
                                          composed_analysis_id: str,
                                          sub_analysis_id: str) -> typing.Optional[dict]:
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}/sub-analyses/{}/code-reuse'
                                                                  .format(composed_analysis_id, sub_analysis_id),
                                                                  method='GET')
        if response.status_code == HTTPStatus.CONFLICT:
            return None

        raise_for_status(response)

        return response.json()

    def get_sub_analysis_metadata_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> dict:
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}/sub-analyses/{}/metadata'
                                                                  .format(composed_analysis_id, sub_analysis_id),
                                                                  method='GET')
        raise_for_status(response)

        return response.json()

    def get_sub_analysis_related_files_by_family_id(self,
                                                    composed_analysis_id: str,
                                                    sub_analysis_id: str,
                                                    family_id: str) -> str:
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/code-reuse/families/{}/find-related-files'.format(
                composed_analysis_id, sub_analysis_id, family_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def get_sub_analysis_account_related_samples_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/get-account-related-samples'.format(composed_analysis_id,
                                                                                   sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def get_sub_analysis_capabilities_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        self.assert_on_premise_above_v21_11()
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/capabilities'.format(composed_analysis_id, sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def generate_sub_analysis_vaccine_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/generate-vaccine'.format(composed_analysis_id, sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def get_strings_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> dict:
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/strings'.format(composed_analysis_id, sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()

    def get_string_related_samples_by_id(self,
                                         composed_analysis_id: str,
                                         sub_analysis_id: str,
                                         string_value: str) -> str:
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/string-related-samples'.format(composed_analysis_id, sub_analysis_id),
            method='POST',
            data={'string_value': string_value})

        raise_for_status(response)

        return response.json()['result_url']

    def get_url_result(self, url: str) -> typing.Optional[Response]:
        response = self.request_with_refresh_expired_access_token(path=url, method='GET')

        raise_for_status(response)

        response_json = response.json()

        if 'error' in response_json:
            raise IntezerError('response error: {}'.format(response_json['error']))

        return response

    def download_file_by_sha256(self, sha256: str, path: str) -> None:
        if os.path.isdir(path):
            path = os.path.join(path, sha256 + '.sample')
        if os.path.isfile(path):
            raise FileExistsError()

        response = self.request_with_refresh_expired_access_token(path='/files/{}/download'.format(sha256),
                                                                  method='GET')

        raise_for_status(response)

        with open(path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

    def index_by_sha256(self, sha256: str, index_as: IndexType, family_name: str = None) -> Response:
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        response = self.request_with_refresh_expired_access_token(path='/files/{}/index'.format(sha256), data=data,
                                                                  method='POST')
        self._assert_index_response_status_code(response)

        return self._get_index_id_from_response(response)

    def index_by_file(self, file_path: str, index_as: IndexType, family_name: str = None) -> Response:
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        with open(file_path, 'rb') as file_to_upload:
            file = {'file': (os.path.basename(file_path), file_to_upload)}

            response = self.request_with_refresh_expired_access_token(path='/files/index',
                                                                      data=data,
                                                                      files=file,
                                                                      method='POST')

        self._assert_index_response_status_code(response)

        return self._get_index_id_from_response(response)

    def get_index_response(self, index_id: str) -> Response:
        response = self.request_with_refresh_expired_access_token(path='/files/index/{}'.format(index_id),
                                                                  method='GET')
        raise_for_status(response)

        return response

    def _set_access_token(self, api_key: str):
        response = requests.post(self.full_url + '/get-access-token',
                                 json={'api_key': api_key},
                                 verify=self._verify_ssl)

        if response.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.BAD_REQUEST):
            raise InvalidApiKey(response)
        if response.status_code != HTTPStatus.OK:
            raise_for_status(response)

        self._access_token = response.json()['result']

    def set_session(self):
        self._session = requests.session()
        self._session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
        self._session.verify = self._verify_ssl
        self._set_access_token(self.api_key)
        self._session.headers['Authorization'] = 'Bearer {}'.format(self._access_token)
        self._session.headers['User-Agent'] = USER_AGENT

    def analyze_url(self, url: str, **additional_parameters) -> typing.Optional[str]:
        self.assert_on_premise_above_v21_11()
        response = self.request_with_refresh_expired_access_token(method='POST',
                                                                  path='/url/',
                                                                  data=dict(url=url, **additional_parameters))
        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    @staticmethod
    def _assert_result_response(ignore_not_found: bool, response: Response):
        statuses_to_ignore = [HTTPStatus.NOT_FOUND] if ignore_not_found else None
        raise_for_status(response, statuses_to_ignore=statuses_to_ignore)

    @staticmethod
    def _param_initialize(disable_dynamic_unpacking: bool,
                          disable_static_unpacking: bool,
                          code_item_type: str = None,
                          zip_password: str = None,
                          **additional_parameters):
        data = {}

        if disable_dynamic_unpacking is not None:
            data['disable_dynamic_execution'] = disable_dynamic_unpacking
        if disable_static_unpacking is not None:
            data['disable_static_extraction'] = disable_static_unpacking
        if code_item_type:
            data['code_item_type'] = code_item_type
        if zip_password:
            data['zip_password'] = zip_password

        data.update(additional_parameters)

        return data

    @staticmethod
    def _assert_analysis_response_status_code(response: Response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise HashDoesNotExistError(response)
        elif response.status_code == HTTPStatus.CONFLICT:
            raise AnalysisIsAlreadyRunning(response)
        elif response.status_code == HTTPStatus.FORBIDDEN:
            raise InsufficientQuota(response)
        elif response.status_code == HTTPStatus.BAD_REQUEST:
            data = response.json()
            error = data.get('error', '')
            raise ServerError('Server returned bad request error: {}'.format(error), response)
        elif response.status_code != HTTPStatus.CREATED:
            raise ServerError('Error in response status code:{}'.format(response.status_code), response)

    @staticmethod
    def _assert_index_response_status_code(response: Response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise HashDoesNotExistError(response)
        elif response.status_code != HTTPStatus.CREATED:
            raise ServerError('Error in response status code:{}'.format(response.status_code), response)

    @staticmethod
    def _get_analysis_id_from_response(response: Response):
        return response.json()['result_url'].split('/')[2]

    @staticmethod
    def _get_index_id_from_response(response: Response):
        return response.json()['result_url'].split('/')[3]

    def assert_on_premise_above_v21_11(self):
        if self.on_premise_version and self.on_premise_version <= OnPremiseVersion.V21_11:
            raise UnsupportedOnPremiseVersion('This endpoint is not available yet on this on premise')


def get_global_api() -> IntezerApi:
    global _global_api

    if not _global_api:
        raise GlobalApiIsNotInitialized()

    return _global_api


def set_global_api(api_key: str = None,
                   api_version: str = None,
                   base_url: str = None,
                   verify_ssl: bool = True,
                   on_premise_version: OnPremiseVersion = None):
    global _global_api
    api_key = api_key or os.environ.get('INTEZER_ANALYZE_API_KEY')
    _global_api = IntezerApi(api_version or API_VERSION,
                             api_key,
                             base_url or BASE_URL,
                             verify_ssl,
                             on_premise_version)


# endregion

# region base_analysis.py

import abc
import datetime
from typing import Any
from typing import Dict
from typing import Optional
from typing import Union

from requests import Response


class BaseAnalysis(metaclass=abc.ABCMeta):
    def __init__(self, api: IntezerApi = None):
        self.status = None
        self.analysis_id = None
        self._api: IntezerApi = api or get_global_api()
        self._report: Optional[Dict[str, Any]] = None

    @abc.abstractmethod
    def _query_status_from_api(self) -> Response:
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApi = None):
        raise NotImplementedError()

    @abc.abstractmethod
    def _send_analyze_to_api(self, **additional_parameters) -> str:
        raise NotImplementedError()

    def wait_for_completion(self,
                            interval: int = None,
                            sleep_before_first_check=False,
                            timeout: Optional[datetime.timedelta] = None):
        """
        Blocks until the analysis is completed
        :param interval: The interval to wait between checks
        :param sleep_before_first_check: Whether to sleep before the first status check
        :param timeout: Maximum duration to wait for analysis completion
        """
        start_time = datetime.datetime.utcnow()
        if not interval:
            interval = CHECK_STATUS_INTERVAL
        if self._is_analysis_running():
            if sleep_before_first_check:
                time.sleep(interval)
            status_code = self.check_status()

            while status_code != AnalysisStatusCode.FINISH:
                timeout_passed = timeout and datetime.datetime.utcnow() - start_time > timeout
                if timeout_passed:
                    raise TimeoutError
                time.sleep(interval)
                status_code = self.check_status()

    def _is_analysis_running(self) -> bool:
        return self.status in (AnalysisStatusCode.CREATED, AnalysisStatusCode.IN_PROGRESS)

    def send(self,
             wait: Union[bool, int] = False,
             wait_timeout: Optional[datetime.timedelta] = None,
             **additional_parameters) -> None:
        if self.analysis_id:
            raise AnalysisHasAlreadyBeenSent()

        self.analysis_id = self._send_analyze_to_api(**additional_parameters)

        self.status = AnalysisStatusCode.CREATED

        if wait:
            if isinstance(wait, int):
                self.wait_for_completion(wait, sleep_before_first_check=True, timeout=wait_timeout)
            else:
                self.wait_for_completion(sleep_before_first_check=True, timeout=wait_timeout)

    def check_status(self) -> AnalysisStatusCode:
        if not self._is_analysis_running():
            raise IntezerError('Analysis is not running')

        response = self._query_status_from_api()
        if response.status_code == HTTPStatus.OK:
            result = response.json()
            if result['status'] == AnalysisStatusCode.FAILED.value:
                self.status = AnalysisStatusCode.FAILED
                raise IntezerError('Analysis failed')
            self._report = result['result']
            self.status = AnalysisStatusCode.FINISH
        elif response.status_code == HTTPStatus.ACCEPTED:
            self.status = AnalysisStatusCode.IN_PROGRESS
        else:
            raise IntezerError('Error in response status code:{}'.format(response.status_code))

        return self.status

    def result(self) -> dict:
        if self._is_analysis_running():
            raise AnalysisIsStillRunning()
        if not self._report:
            raise ReportDoesNotExistError()

        return self._report

    def set_report(self, report: dict):
        if not report:
            raise ValueError('Report can not be None')

        self.analysis_id = report['analysis_id']
        self._report = report
        self.status = AnalysisStatusCode.FINISH

    def _assert_analysis_finished(self):
        if self._is_analysis_running():
            raise AnalysisIsStillRunning()
        if self.status != AnalysisStatusCode.FINISH:
            raise IntezerError('Analysis not finished successfully')


# endregion

# region operation.py
import datetime
import time
from typing import Optional


class Operation:

    def __init__(self, status: AnalysisStatusCode, url: str, api: IntezerApi = None):
        self.status = status
        self.url = url
        self.result = None
        self._api = api or get_global_api()

    def get_result(self):
        if self.status != AnalysisStatusCode.FINISH:

            operation_result = self._api.get_url_result(self.url)

            if handle_response_status(operation_result.status_code):
                self.result = operation_result.json()['result']
                self.status = AnalysisStatusCode.FINISH
            else:
                raise SubAnalysisOperationStillRunning('operation')
        return self.result

    def wait_for_completion(self,
                            interval: int = None,
                            sleep_before_first_check=False,
                            wait_timeout: Optional[datetime.timedelta] = None) -> None:
        start_time = datetime.datetime.utcnow()
        if not interval:
            interval = CHECK_STATUS_INTERVAL

        if sleep_before_first_check:
            time.sleep(interval)
        operation_result = self._api.get_url_result(self.url)

        while not handle_response_status(operation_result.status_code):
            timeout_passed = wait_timeout and datetime.datetime.utcnow() - start_time > wait_timeout
            if timeout_passed:
                raise TimeoutError
            time.sleep(interval)
            operation_result = self._api.get_url_result(self.url)

        self.status = AnalysisStatusCode.FINISH
        self.result = operation_result.json()['result']


def handle_response_status(status):
    if status not in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
        raise IntezerError('Error in response status code:{}'.format(status))

    return status == HTTPStatus.OK


# endregion

# region sub_analysis.py
import datetime
import typing


class SubAnalysis:
    def __init__(self, analysis_id: str, composed_analysis_id: str, sha256: str, source: str, api: IntezerApi = None):
        self.composed_analysis_id = composed_analysis_id
        self.analysis_id = analysis_id
        self.sha256 = sha256
        self.source = source
        self._api = api or get_global_api()
        self._code_reuse = None
        self._metadata = None
        self._capabilities = None
        self._operations = {}

    @property
    def code_reuse(self):
        if self._code_reuse is None:
            self._code_reuse = self._api.get_sub_analysis_code_reuse_by_id(self.composed_analysis_id, self.analysis_id)
        return self._code_reuse

    @property
    def metadata(self):
        if self._metadata is None:
            self._metadata = self._api.get_sub_analysis_metadata_by_id(self.composed_analysis_id, self.analysis_id)
        return self._metadata

    def find_related_files(self,
                           family_id: str,
                           wait: typing.Union[bool, int] = False,
                           wait_timeout: typing.Optional[datetime.timedelta] = None) -> Operation:
        result_url = self._api.get_sub_analysis_related_files_by_family_id(self.composed_analysis_id,
                                                                           self.analysis_id,
                                                                           family_id)
        return self._handle_operation(family_id, result_url, wait, wait_timeout)

    def get_account_related_samples(self,
                                    wait: typing.Union[bool, int] = False,
                                    wait_timeout: typing.Optional[datetime.timedelta] = None) -> typing.Optional[
        Operation]:
        try:
            result_url = self._api.get_sub_analysis_account_related_samples_by_id(self.composed_analysis_id,
                                                                                  self.analysis_id)
        except Exception:
            return None

        return self._handle_operation('Account related samples', result_url, wait, wait_timeout)

    def generate_vaccine(self,
                         wait: typing.Union[bool, int] = False,
                         wait_timeout: typing.Optional[datetime.timedelta] = None) -> Operation:
        result_url = self._api.generate_sub_analysis_vaccine_by_id(self.composed_analysis_id, self.analysis_id)
        return self._handle_operation('Vaccine', result_url, wait, wait_timeout)

    def get_capabilities(self,
                         wait: typing.Union[bool, int] = False,
                         wait_timeout: typing.Optional[datetime.timedelta] = None) -> Operation:
        result_url = self._api.get_sub_analysis_capabilities_by_id(self.composed_analysis_id, self.analysis_id)
        return self._handle_operation('Capabilities', result_url, wait, wait_timeout)

    def get_strings(self,
                    wait: typing.Union[bool, int] = False,
                    wait_timeout: typing.Optional[datetime.timedelta] = None) -> Operation:
        result = self._api.get_strings_by_id(self.composed_analysis_id, self.analysis_id)
        return self._handle_operation('Strings', result['result_url'], wait, wait_timeout)

    def get_string_related_samples(self,
                                   string_value: str,
                                   wait: typing.Union[bool, int] = False,
                                   wait_timeout: typing.Optional[datetime.timedelta] = None) -> Operation:
        result_url = self._api.get_string_related_samples_by_id(self.composed_analysis_id,
                                                                self.analysis_id,
                                                                string_value)
        return self._handle_operation(string_value, result_url, wait, wait_timeout)

    def _handle_operation(self,
                          operation: str,
                          url: str,
                          wait: typing.Union[bool, int],
                          wait_timeout: typing.Optional[datetime.timedelta]) -> Operation:
        if operation not in self._operations:
            self._operations[operation] = Operation(AnalysisStatusCode.IN_PROGRESS, url, api=self._api)

            if wait:
                if isinstance(wait, int):
                    self._operations[operation].wait_for_completion(wait,
                                                                    sleep_before_first_check=True,
                                                                    wait_timeout=wait_timeout)
                else:
                    self._operations[operation].wait_for_completion(sleep_before_first_check=True,
                                                                    wait_timeout=wait_timeout)

        return self._operations[operation]

    def download_file(self, path: str):
        self._api.download_file_by_sha256(self.sha256, path)


# endregion

# region analysis.py
import logging
import os
from http import HTTPStatus
from typing import BinaryIO
from typing import Optional

import requests
from requests import Response

logger = logging.getLogger(__name__)


class FileAnalysis(BaseAnalysis):
    def __init__(self,
                 file_path: str = None,
                 file_hash: str = None,
                 file_stream: BinaryIO = None,
                 disable_dynamic_unpacking: bool = None,
                 disable_static_unpacking: bool = None,
                 api: IntezerApi = None,
                 file_name: str = None,
                 code_item_type: str = None,
                 zip_password: str = None):
        super().__init__(api)

        if [file_path, file_hash, file_stream].count(None) != 2:
            raise ValueError('Choose between file hash, file stream or file path analysis')

        if file_hash and code_item_type:
            logger.warning('Analyze by hash ignores code item type')

        if code_item_type and code_item_type not in [c.value for c in CodeItemType]:
            raise ValueError('Invalid code item type, possible code item types are: file, memory module')

        self._file_hash = file_hash
        self._disable_dynamic_unpacking = disable_dynamic_unpacking
        self._disable_static_unpacking = disable_static_unpacking
        self._file_path = file_path
        self._file_stream = file_stream
        self._file_name = file_name
        self._code_item_type = code_item_type
        self._zip_password = zip_password
        self._sub_analyses = None
        self._root_analysis = None
        self._iocs_report = None
        self._dynamic_ttps_report = None

        if self._file_path and not self._file_name:
            self._file_name = os.path.basename(file_path)

        if self._zip_password:
            if self._file_name:
                if not self._file_name.endswith('.zip'):
                    self._file_name += '.zip'
            else:
                self._file_name = 'file.zip'

    @classmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApi = None) -> Optional['FileAnalysis']:
        api = api or get_global_api()
        response = api.get_file_analysis_response(analysis_id, True)
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None
        response_json = response.json()

        _assert_analysis_status(response_json)

        analysis_report = response_json.get('result')
        if not analysis_report:
            return None

        analysis = cls(file_hash=analysis_report['sha256'], api=api)
        analysis.set_report(analysis_report)

        return analysis

    @classmethod
    def from_latest_hash_analysis(cls,
                                  file_hash: str,
                                  api: IntezerApi = None,
                                  private_only: bool = False,
                                  **additional_parameters) -> Optional['FileAnalysis']:
        api = api or get_global_api()
        analysis_report = api.get_latest_analysis(file_hash, private_only, **additional_parameters)

        if not analysis_report:
            return None

        analysis = cls(file_hash=file_hash, api=api)
        analysis.set_report(analysis_report)

        return analysis

    def _query_status_from_api(self) -> Response:
        return self._api.get_file_analysis_response(self.analysis_id, False)

    def _send_analyze_to_api(self, **additional_parameters) -> str:
        if self._file_hash:
            return self._api.analyze_by_hash(self._file_hash,
                                             self._disable_dynamic_unpacking,
                                             self._disable_static_unpacking,
                                             **additional_parameters)
        else:
            return self._api.analyze_by_file(self._file_path,
                                             self._file_stream,
                                             disable_dynamic_unpacking=self._disable_dynamic_unpacking,
                                             disable_static_unpacking=self._disable_static_unpacking,
                                             file_name=self._file_name,
                                             code_item_type=self._code_item_type,
                                             zip_password=self._zip_password,
                                             **additional_parameters)

    def get_sub_analyses(self):
        if self._sub_analyses is None and self.analysis_id:
            self._init_sub_analyses()
        return self._sub_analyses

    def get_root_analysis(self) -> SubAnalysis:
        if self._root_analysis is None and self.analysis_id:
            self._init_sub_analyses()
        return self._root_analysis

    def _init_sub_analyses(self):
        all_sub_analysis = self._api.get_sub_analyses_by_id(self.analysis_id)
        self._sub_analyses = []
        for sub_analysis in all_sub_analysis:
            sub_analysis_object = SubAnalysis(sub_analysis['sub_analysis_id'],
                                              self.analysis_id,
                                              sub_analysis['sha256'],
                                              sub_analysis['source'],
                                              api=self._api)
            if sub_analysis_object.source == 'root':
                self._root_analysis = sub_analysis_object
            else:
                self._sub_analyses.append(sub_analysis_object)

    def download_file(self, path: str):
        self._api.download_file_by_sha256(self.result()['sha256'], path)

    @property
    def iocs(self) -> dict:
        self._assert_analysis_finished()
        if not self._iocs_report:
            try:
                self._iocs_report = self._api.get_iocs(self.analysis_id)
            except requests.HTTPError as e:
                if e.response.status_code == HTTPStatus.NOT_FOUND:
                    self._iocs_report = None
                else:
                    raise

        return self._iocs_report

    @property
    def dynamic_ttps(self) -> dict:
        self._assert_analysis_finished()
        if not self._dynamic_ttps_report:
            try:
                self._dynamic_ttps_report = self._api.get_dynamic_ttps(self.analysis_id)
            except requests.HTTPError as e:
                if e.response.status_code == HTTPStatus.NOT_FOUND:
                    self._dynamic_ttps_report = None
                else:
                    raise

        return self._dynamic_ttps_report


@deprecated('This method is deprecated, use FileAnalysis.from_latest_hash_analysis instead to be explict')
def get_latest_analysis(file_hash: str,
                        api: IntezerApi = None,
                        private_only: bool = False,
                        **additional_parameters) -> Optional[FileAnalysis]:
    return FileAnalysis.from_latest_hash_analysis(file_hash, api, private_only, **additional_parameters)


@deprecated('This method is deprecated, use FileAnalysis.from_analysis_by_id instead to be explict')
def get_file_analysis_by_id(analysis_id: str, api: IntezerApi = None) -> Optional[FileAnalysis]:
    return FileAnalysis.from_analysis_id(analysis_id, api)


@deprecated('This method is deprecated, use FileAnalysis.from_analysis_by_id instead to be explict')
def get_analysis_by_id(analysis_id: str, api: IntezerApi = None) -> Optional[FileAnalysis]:
    return get_file_analysis_by_id(analysis_id, api)


Analysis = FileAnalysis


class UrlAnalysis(BaseAnalysis):
    def __init__(self, url: str, api: IntezerApi = None):
        super().__init__(api)
        self._api.assert_on_premise_above_v21_11()
        self.url = url
        self._file_analysis: Optional[FileAnalysis] = None

    @classmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApi = None) -> Optional['UrlAnalysis']:
        api = api or get_global_api()
        response = api.get_url_analysis_response(analysis_id, True)
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        response_json = response.json()
        _assert_analysis_status(response_json)

        analysis_report = response_json.get('result')
        if not analysis_report:
            return None

        analysis = UrlAnalysis(analysis_report['submitted_url'], api=api)
        analysis.set_report(analysis_report)

        return analysis

    def _query_status_from_api(self) -> Response:
        return self._api.get_url_analysis_response(self.analysis_id, False)

    def _send_analyze_to_api(self, **additional_parameters) -> str:
        return self._api.analyze_url(self.url)

    @property
    def downloaded_file_analysis(self) -> Optional[FileAnalysis]:
        if self.status != AnalysisStatusCode.FINISH:
            raise
        if self._file_analysis:
            return self._file_analysis

        if 'downloaded_file' not in self._report:
            return None

        file_analysis_id = self._report['downloaded_file']['analysis_id']
        self._file_analysis = get_file_analysis_by_id(file_analysis_id)
        return self._file_analysis


@deprecated('This method is deprecated, use UrlAnalysis.from_analysis_by_id instead to be explict')
def get_url_analysis_by_id(analysis_id: str, api: IntezerApi = None) -> Optional[UrlAnalysis]:
    return UrlAnalysis.from_analysis_id(analysis_id, api)


def _assert_analysis_status(response: dict):
    if response['status'] in (AnalysisStatusCode.IN_PROGRESS.value,
                              AnalysisStatusCode.QUEUED.value):
        raise AnalysisIsStillRunning()
    if response['status'] == AnalysisStatusCode.FAILED.value:
        raise AnalysisFailedError()


# endregion

from AnomaliEnrichment import AnomaliEnrichment
from AnomaliEnrichment import CompositeItem
from AnomaliEnrichment import ItemInWidget
from AnomaliEnrichment import ItemTypes
from AnomaliEnrichment import TableWidget
from AnomaliEnrichment import TextWidget

SEVERITY_TO_NAME = {1: 'low', 2: 'medium', 3: 'high'}
REQUESTER = 'anomali'
MAX_TIMEOUT = 25


def activation(api_key: str):
    set_global_api(api_key)
    get_global_api().request_with_refresh_expired_access_token('GET', '/accounts/me')


def enrich_hash(ae: AnomaliEnrichment, hash_value: str, wait_timeout: datetime.timedelta, private_only: bool):
    file_analysis = FileAnalysis.from_latest_hash_analysis(hash_value, private_only=private_only, requester=REQUESTER)
    if not file_analysis:
        file_analysis = FileAnalysis(file_hash=hash_value)
        try:
            file_analysis.send(wait=True, wait_timeout=wait_timeout, requester=REQUESTER)
        except HashDoesNotExistError:
            ae.addWidget(TextWidget(ItemInWidget(ItemTypes.String, 'Hash not found in Intezer')))
            return
        except TimeoutError:
            ae.addWidget(TextWidget(ItemInWidget(
                ItemTypes.String,
                'Time out waiting to Intezer result, you can check the result at:'))
            )
            ae.addWidget(TextWidget(ItemInWidget(
                ItemTypes.Link,
                f'https://analyze.intezer.com/analyses/{file_analysis.analysis_id}'))
            )
            return

    analysis_details = file_analysis.result()

    basic_table_widget = TableWidget('Analysis Details', ['Field', 'Value'], columnWidths=['20%', '80%'])

    for key, value in analysis_details.items():
        key_widget = ItemInWidget(ItemTypes.String, key.replace('_', ' ').replace('_', ' ').capitalize())
        if key == 'analysis_url':
            basic_table_widget.addRowOfItems([
                key_widget,
                ItemInWidget(ItemTypes.Link, value, 'View in Intezer Analyze')
            ])
        else:
            basic_table_widget.addRowOfItems([
                key_widget,
                ItemInWidget(ItemTypes.String, value)
            ])

    ae.addWidget(basic_table_widget)

    iocs = file_analysis.iocs
    if iocs:
        if iocs.get('network'):
            network_iocs_table_widget = TableWidget('Network IOCs',
                                                    ['Value', 'Type', 'Source'],
                                                    columnWidths=['70%', '10%', '20%'])

            for ioc in iocs['network']:
                ioc_type = ioc['type']
                type_title = 'IP' if ioc_type == 'ip' else ioc_type.capitalize()
                item_value = item_label = ioc['ioc']
                if ioc_type in ('ip', 'url', 'domain'):
                    item_value = f"detail/v2/{ioc_type}?value={ioc['ioc']}"
                    cell_type = ItemTypes.Link
                else:
                    cell_type = ItemTypes.String
                network_iocs_table_widget.addRowOfItems([ItemInWidget(cell_type, item_value, item_label),
                                                         ItemInWidget(ItemTypes.String, type_title),
                                                         ItemInWidget(ItemTypes.String, ','.join(ioc['source']))])

            ae.addWidget(network_iocs_table_widget)

        if iocs.get('files'):
            files_iocs_table_widget = TableWidget('Files IOCs',
                                                  ['SHA256', 'Path', 'Type', 'Classification'],
                                                  columnWidths=['35%', '45%', '10%', '10%'])
            for file in iocs['files']:
                classification = file['verdict'].capitalize()
                if file.get('family'):
                    classification = f'{classification} ({file["family"]})'
                files_iocs_table_widget.addRowOfItems([
                    ItemInWidget(ItemTypes.Link, f"detail/v2/hash?value={file['sha256']}", file['sha256']),
                    ItemInWidget(ItemTypes.String, file['path']),
                    ItemInWidget(ItemTypes.String, file['type'].replace('_', ' ').capitalize()),
                    ItemInWidget(ItemTypes.String, classification),
                ])

            ae.addWidget(files_iocs_table_widget)

    if file_analysis.dynamic_ttps:
        ttps_table_widget = TableWidget('Signatures',
                                        ['MITRE ATT&CK', 'Technique', 'Severity', 'Details'],
                                        columnWidths=['35%', '30%', '5%', '30%'])
        for ttp in sorted(file_analysis.dynamic_ttps, key=lambda t: t['severity'], reverse=True):
            if 'data' in ttp:
                details_item = CompositeItem(onSeparateLines=True)
                for additional_data in ttp['data']:
                    details_item.addItemInWidget(
                        ItemInWidget(ItemTypes.String,
                                     ','.join(f'{key}:{value}' for key, value in additional_data.items()))
                    )
            else:
                details_item = ItemInWidget(ItemTypes.String, '')

            ttps_table_widget.addRowOfItems([
                ItemInWidget(ItemTypes.String, ttp.get('ttp', {}).get('ttp', '')),
                ItemInWidget(ItemTypes.String, ttp['description']),
                ItemInWidget(ItemTypes.String, SEVERITY_TO_NAME[ttp['severity']].capitalize()),
                details_item
            ])

        ae.addWidget(ttps_table_widget)


def main():
    ae = AnomaliEnrichment()
    ae.parseArguments()

    transform_name = ae.getTransformName()
    entity_value = ae.getEntityValue()

    api_key = ae.getCredentialValue('api_key')
    private_only = ae.getCredentialValue('optional_only_private_analysis')
    if private_only is None:
        private_only = False
    else:
        private_only = private_only.lower()
        if private_only in ['yes', 'true']:
            private_only = True
        elif private_only in ['no', 'false']:
            private_only = False
        else:
            ae.addMessage("ERROR", 'Wrong optional_only_private_analysis format, '
                                   'use one of the following: yes, no, true,false.')
            ae.addException('Input Error : Wrong optional_only_private_analysis format')
            return

    wait_timeout = ae.getCredentialValue('optional_analysis_wait_timeout')
    if wait_timeout:
        try:
            wait_timeout = int(wait_timeout)
            if wait_timeout < 1:
                message = 'Wrong optional_analysis_wait_timeout, must be a positive number'
                ae.addMessage('ERROR', message)
                ae.addException(f'Input Error: {message}')
                return
            elif wait_timeout > MAX_TIMEOUT:
                message = f'Wrong optional_analysis_wait_timeout, must be lower or equal to {MAX_TIMEOUT}'
                ae.addMessage('ERROR', message)
                ae.addException(f'Input Error: {message}')
                return
        except ValueError:
            message = 'Wrong optional_analysis_wait_timeout format, must be a number'
            ae.addMessage('ERROR', message)
            ae.addException(f'Input Error: {message}')
            return
    else:
        wait_timeout = MAX_TIMEOUT

    wait_timeout = datetime.timedelta(seconds=wait_timeout)

    if transform_name is None:
        ae.addException('Transform Name is not provided')

    elif entity_value is None:
        ae.addException('Entity Value is not provided')

    elif api_key is None:
        # Without any calls to addMessage, whatever is given to addException will be shown to the user in the event of
        # an error. Therefore, any errors that can occur during the running of an enrichment should make sure to call
        # addMessage with the "ERROR" parameter to ensure that that is what is shown to the user. Calls to addException
        # should only be used for logging.
        ae.addMessage("ERROR", "No API Key provided.")
        ae.addException('Input Error : Missing API key')
    else:
        set_global_api(api_key)
        try:
            if transform_name == 'activation':
                activation(api_key)
            elif transform_name == 'enrichHash':
                try:
                    enrich_hash(ae, entity_value, wait_timeout, private_only)
                except Exception as ex:
                    ae.addException('Unexpected exception : ' + str(ex))
            else:
                ae.addException('Transform Name is unknown : ' + transform_name)
        except Exception as e:
            ae.addMessage("ERROR", "An Unexpected error occurred, please try again. "
                                   "If the error persists please contact support.")
            ae.addException(str(e))

    ae.returnOutput()


if __name__ == '__main__':
    main()
