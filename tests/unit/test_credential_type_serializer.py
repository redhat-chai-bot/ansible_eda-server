#  Copyright 2024 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import copy
from unittest.mock import patch

import pytest

from aap_eda.api.serializers.credential_type import (
    CredentialTypeSerializer,
)
from aap_eda.core import models

SAMPLE_INPUTS = {
    "fields": [
        {
            "id": "username",
            "label": "Username",
            "type": "string",
        },
        {
            "id": "password",
            "label": "Password",
            "type": "string",
            "secret": True,
        },
        {
            "id": "ssh_key_data",
            "label": "SCM Private Key",
            "type": "string",
            "format": "ssh_private_key",
            "secret": True,
            "multiline": True,
        },
        {
            "id": "verify_ssl",
            "label": "Verify SSL",
            "type": "boolean",
        },
        {
            "id": "host",
            "label": "Host",
            "type": "string",
            "help_text": "The hostname.",
        },
    ],
    "required": ["host"],
}

MOCK_PATTERN = r"^[\p{L}\p{N}][\p{L}\p{N}\p{M}_ .@\-]*\Z"
MOCK_DESCRIPTION = "Must not contain special characters."


@pytest.mark.django_db
class TestCredentialTypeValidationPatterns:
    """Tests for validation pattern injection in
    CredentialTypeSerializer.to_representation()."""

    @patch(
        "aap_eda.api.serializers.credential_type"
        ".CLEAN_TEXT_DESCRIPTION",
        MOCK_DESCRIPTION,
    )
    @patch(
        "aap_eda.api.serializers.credential_type"
        ".CLEAN_TEXT_PATTERN",
        MOCK_PATTERN,
    )
    @patch(
        "aap_eda.api.serializers.credential_type"
        ".get_setting",
        return_value=True,
    )
    def test_patterns_injected_when_validation_enabled(
        self, mock_get_setting
    ):
        """When validation is enabled, string non-secret fields
        should have pattern and pattern_description injected."""
        credential_type = models.CredentialType.objects.create(
            name="test-type-enabled",
            inputs=copy.deepcopy(SAMPLE_INPUTS),
        )
        serializer = CredentialTypeSerializer(credential_type)
        data = serializer.data

        fields = data["inputs"]["fields"]

        # username: type=string, no secret -> should have pattern
        username = fields[0]
        assert username["id"] == "username"
        assert username["pattern"] == MOCK_PATTERN
        assert (
            username["pattern_description"]
            == MOCK_DESCRIPTION
        )

        # host: type=string, no secret -> should have pattern
        host = fields[4]
        assert host["id"] == "host"
        assert host["pattern"] == MOCK_PATTERN
        assert (
            host["pattern_description"] == MOCK_DESCRIPTION
        )

        mock_get_setting.assert_called_with(
            "ENHANCED_INPUT_VALIDATION_ENABLED", False
        )

    @patch(
        "aap_eda.api.serializers.credential_type"
        ".CLEAN_TEXT_DESCRIPTION",
        MOCK_DESCRIPTION,
    )
    @patch(
        "aap_eda.api.serializers.credential_type"
        ".CLEAN_TEXT_PATTERN",
        MOCK_PATTERN,
    )
    @patch(
        "aap_eda.api.serializers.credential_type"
        ".get_setting",
        return_value=True,
    )
    def test_secret_fields_excluded(self, mock_get_setting):
        """Secret fields should never get pattern injected,
        regardless of the validation toggle."""
        credential_type = models.CredentialType.objects.create(
            name="test-type-secrets",
            inputs=copy.deepcopy(SAMPLE_INPUTS),
        )
        serializer = CredentialTypeSerializer(credential_type)
        data = serializer.data

        fields = data["inputs"]["fields"]

        # password: secret=True -> no pattern
        password = fields[1]
        assert password["id"] == "password"
        assert "pattern" not in password
        assert "pattern_description" not in password

        # ssh_key_data: secret=True -> no pattern
        ssh_key = fields[2]
        assert ssh_key["id"] == "ssh_key_data"
        assert "pattern" not in ssh_key
        assert "pattern_description" not in ssh_key

    @patch(
        "aap_eda.api.serializers.credential_type"
        ".CLEAN_TEXT_DESCRIPTION",
        MOCK_DESCRIPTION,
    )
    @patch(
        "aap_eda.api.serializers.credential_type"
        ".CLEAN_TEXT_PATTERN",
        MOCK_PATTERN,
    )
    @patch(
        "aap_eda.api.serializers.credential_type"
        ".get_setting",
        return_value=True,
    )
    def test_non_string_fields_excluded(
        self, mock_get_setting
    ):
        """Non-string type fields (e.g. boolean) should not get
        pattern injected."""
        credential_type = models.CredentialType.objects.create(
            name="test-type-boolean",
            inputs=copy.deepcopy(SAMPLE_INPUTS),
        )
        serializer = CredentialTypeSerializer(credential_type)
        data = serializer.data

        fields = data["inputs"]["fields"]

        # verify_ssl: type=boolean -> no pattern
        verify_ssl = fields[3]
        assert verify_ssl["id"] == "verify_ssl"
        assert "pattern" not in verify_ssl
        assert "pattern_description" not in verify_ssl

    @patch(
        "aap_eda.api.serializers.credential_type"
        ".get_setting",
        return_value=False,
    )
    def test_no_patterns_when_validation_disabled(
        self, mock_get_setting
    ):
        """When validation is disabled, no fields should have
        pattern or pattern_description."""
        credential_type = models.CredentialType.objects.create(
            name="test-type-disabled",
            inputs=copy.deepcopy(SAMPLE_INPUTS),
        )
        serializer = CredentialTypeSerializer(credential_type)
        data = serializer.data

        for field in data["inputs"]["fields"]:
            assert "pattern" not in field, (
                f"Field '{field['id']}' should not have "
                f"pattern when validation is disabled"
            )
            assert "pattern_description" not in field, (
                f"Field '{field['id']}' should not have "
                f"pattern_description when validation "
                f"is disabled"
            )

    @patch(
        "aap_eda.api.serializers.credential_type"
        ".get_setting",
        return_value=True,
    )
    def test_empty_inputs_handled(self, mock_get_setting):
        """Credential types with empty inputs should be handled
        gracefully."""
        credential_type = models.CredentialType.objects.create(
            name="test-type-empty",
            inputs={},
        )
        serializer = CredentialTypeSerializer(credential_type)
        data = serializer.data

        assert data["inputs"] == {}

    @patch(
        "aap_eda.api.serializers.credential_type"
        ".get_setting",
        return_value=True,
    )
    def test_none_inputs_handled(self, mock_get_setting):
        """Credential types with None-like inputs should be
        handled gracefully."""
        credential_type = models.CredentialType.objects.create(
            name="test-type-none",
            inputs=None,
        )
        serializer = CredentialTypeSerializer(credential_type)
        data = serializer.data

        # Should not raise; inputs may be None or null
        assert data["inputs"] is None

    @patch(
        "aap_eda.api.serializers.credential_type"
        ".CLEAN_TEXT_DESCRIPTION",
        MOCK_DESCRIPTION,
    )
    @patch(
        "aap_eda.api.serializers.credential_type"
        ".CLEAN_TEXT_PATTERN",
        MOCK_PATTERN,
    )
    @patch(
        "aap_eda.api.serializers.credential_type"
        ".get_setting",
        return_value=True,
    )
    def test_original_inputs_not_mutated(
        self, mock_get_setting
    ):
        """The original model inputs should not be mutated by
        the serializer."""
        original_inputs = copy.deepcopy(SAMPLE_INPUTS)
        credential_type = models.CredentialType.objects.create(
            name="test-type-mutation",
            inputs=copy.deepcopy(SAMPLE_INPUTS),
        )
        serializer = CredentialTypeSerializer(credential_type)
        serializer.data  # trigger serialization

        # Refresh from DB to check stored value
        credential_type.refresh_from_db()
        assert credential_type.inputs == original_inputs
