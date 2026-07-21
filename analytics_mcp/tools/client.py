# Copyright 2025 Google LLC All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Client initialization for the Google Analytics APIs."""

import contextlib
import subprocess
import threading
from importlib import metadata
from unittest.mock import patch

import google.auth
from google.analytics import (
    admin_v1alpha,
    admin_v1beta,
    data_v1alpha,
    data_v1beta,
)
from google.api_core.gapic_v1.client_info import ClientInfo


def _get_package_version_with_fallback():
    """Returns the version of the package.

    Falls back to 'unknown' if the version can't be resolved.
    """
    try:
        return metadata.version("analytics-mcp")
    except metadata.PackageNotFoundError:
        return "unknown"


_CLIENT_INFO = ClientInfo(
    user_agent=f"analytics-mcp/{_get_package_version_with_fallback()}"
)

_READ_ONLY_ANALYTICS_SCOPE = (
    "https://www.googleapis.com/auth/analytics.readonly"
)
_EDIT_ANALYTICS_SCOPE = "https://www.googleapis.com/auth/analytics.edit"

_client_lock = threading.Lock()
_CREDENTIALS_BY_SCOPES = {}


@contextlib.contextmanager
def prevent_stdio_inheritance():
    """Prevents child processes from inheriting the parent's stdio handles.

    Fixes a deadlock on Windows where `google.auth.default()` spawns `gcloud`
    via subprocess without redirecting stdin, causing it to inherit the
    ProactorEventLoop's overlapping I/O handles used by MCP's stdio transport.
    """
    original_popen = subprocess.Popen

    def safe_popen(*args, **kwargs):
        if kwargs.get("stdin") is None:
            kwargs["stdin"] = subprocess.DEVNULL
        return original_popen(*args, **kwargs)

    with patch("subprocess.Popen", new=safe_popen):
        yield


def _get_credentials(write: bool = False):
    scopes = (
        (_EDIT_ANALYTICS_SCOPE,)
        if write
        else (_READ_ONLY_ANALYTICS_SCOPE,)
    )
    if scopes not in _CREDENTIALS_BY_SCOPES:
        with prevent_stdio_inheritance():
            credentials, _ = google.auth.default(scopes=list(scopes))
        _CREDENTIALS_BY_SCOPES[scopes] = credentials
    return _CREDENTIALS_BY_SCOPES[scopes]


def create_admin_api_client(
    write: bool = False,
) -> admin_v1beta.AnalyticsAdminServiceClient:
    """Returns the Google Analytics Admin API client.

    Args:
        write: Requests the analytics.edit OAuth scope when True.
    """
    with _client_lock:
        return admin_v1beta.AnalyticsAdminServiceClient(
            client_info=_CLIENT_INFO,
            credentials=_get_credentials(write=write),
        )


def create_data_api_client() -> data_v1beta.BetaAnalyticsDataClient:
    """Returns the Google Analytics Data API client."""
    with _client_lock:
        return data_v1beta.BetaAnalyticsDataClient(
            client_info=_CLIENT_INFO,
            credentials=_get_credentials(write=False),
        )


def create_admin_alpha_api_client(
    write: bool = False,
) -> admin_v1alpha.AnalyticsAdminServiceClient:
    """Returns the Google Analytics Admin API (alpha) client.

    Args:
        write: Requests the analytics.edit OAuth scope when True.
    """
    with _client_lock:
        return admin_v1alpha.AnalyticsAdminServiceClient(
            client_info=_CLIENT_INFO,
            credentials=_get_credentials(write=write),
        )


def create_data_api_alpha_client() -> data_v1alpha.AlphaAnalyticsDataClient:
    """Returns the Google Analytics Data API (Alpha) client."""
    with _client_lock:
        return data_v1alpha.AlphaAnalyticsDataClient(
            client_info=_CLIENT_INFO,
            credentials=_get_credentials(write=False),
        )
