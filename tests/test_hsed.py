"""
tests/test_hsed.py
──────────────────
Unit tests for the HSED permission framework.
Run with: python -m pytest tests/ -v
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure the package root is on sys.path when running tests directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from hsed import (
    Bit,
    HSEDPermissionError,
    HSEDValidationError,
    Policy,
    PermissionScope,
    Role,
    RoleConflictError,
    RoleNotFoundError,
    active_bits,
    builtin_role,
    combine,
    enforce,
    has_permission,
    intersect,
    parse_permission_string,
    permission_string,
    subtract,
    validate_permission,
)


# ===========================================================================
# Bit enum
# ===========================================================================

class TestBit:
    def test_values(self):
        assert Bit.HASH.value    == 8
        assert Bit.SIGN.value    == 4
        assert Bit.ENCRYPT.value == 2
        assert Bit.DECRYPT.value == 1
        assert Bit.NONE.value    == 0

    def test_combination(self):
        # Bit flags support | operator
        full = Bit.HASH | Bit.SIGN | Bit.ENCRYPT | Bit.DECRYPT
        assert int(full) == 15


# ===========================================================================
# Permission helpers
# ===========================================================================

class TestValidatePermission:
    def test_valid_boundaries(self):
        for v in [0, 1, 7, 8, 15]:
            validate_permission(v)  # should not raise

    def test_negative(self):
        with pytest.raises(HSEDValidationError):
            validate_permission(-1)

    def test_too_large(self):
        with pytest.raises(HSEDValidationError):
            validate_permission(16)

    def test_wrong_type(self):
        with pytest.raises(HSEDValidationError):
            validate_permission("12")  # type: ignore


class TestHasPermission:
    def test_has(self):
        assert has_permission(15, Bit.HASH) is True
        assert has_permission(12, Bit.SIGN) is True
        assert has_permission(3,  Bit.DECRYPT) is True

    def test_lacks(self):
        assert has_permission(12, Bit.DECRYPT) is False
        assert has_permission(3,  Bit.HASH) is False
        assert has_permission(0,  Bit.SIGN) is False


class TestPermissionString:
    @pytest.mark.parametrize("value,expected", [
        (15, "HSED"),
        (12, "HS--"),
        (3,  "--ED"),
        (9,  "H--D"),
        (10, "H-E-"),
        (8,  "H---"),
        (0,  "----"),
    ])
    def test_string(self, value, expected):
        assert permission_string(value) == expected

    def test_invalid(self):
        with pytest.raises(HSEDValidationError):
            permission_string(99)


class TestParsePermissionString:
    def test_full(self):
        assert parse_permission_string("HSED") == 15

    def test_padded(self):
        assert parse_permission_string("HS--") == 12

    def test_compact(self):
        assert parse_permission_string("ED") == 3

    def test_lowercase(self):
        assert parse_permission_string("hs") == 12

    def test_unknown_char(self):
        with pytest.raises(HSEDValidationError):
            parse_permission_string("HX")


class TestActiveBits:
    def test_full(self):
        bits = active_bits(15)
        assert bits == [Bit.HASH, Bit.SIGN, Bit.ENCRYPT, Bit.DECRYPT]

    def test_signer(self):
        bits = active_bits(12)
        assert bits == [Bit.HASH, Bit.SIGN]

    def test_empty(self):
        assert active_bits(0) == []


class TestCombineIntersectSubtract:
    def test_combine(self):
        assert combine(12, 3) == 15
        assert combine(8, 4) == 12

    def test_intersect(self):
        assert intersect(15, 12) == 12
        assert intersect(12, 3) == 0

    def test_subtract(self):
        assert subtract(15, 3) == 12   # remove E+D from full
        assert subtract(12, 4) == 8    # remove S from HS


# ===========================================================================
# Role
# ===========================================================================

class TestRole:
    def test_creation(self):
        r = Role("test", permissions=12)
        assert r.name == "test"
        assert r.permissions == 12
        assert r.label == "HS--"

    def test_can(self):
        r = Role("signer", permissions=12)
        assert r.can(Bit.HASH) is True
        assert r.can(Bit.SIGN) is True
        assert r.can(Bit.ENCRYPT) is False
        assert r.can(Bit.DECRYPT) is False

    def test_require_pass(self):
        r = Role("signer", permissions=12)
        r.require(Bit.HASH)  # no exception

    def test_require_fail(self):
        r = Role("signer", permissions=12)
        with pytest.raises(HSEDPermissionError) as exc_info:
            r.require(Bit.DECRYPT)
        assert "signer" in str(exc_info.value)
        assert "DECRYPT" in str(exc_info.value)

    def test_invalid_permissions(self):
        with pytest.raises(HSEDValidationError):
            Role("bad", permissions=99)

    def test_empty_name(self):
        with pytest.raises(HSEDValidationError):
            Role("", permissions=12)

    def test_grant(self):
        r = Role("x", permissions=12)
        r2 = r.grant(3)
        assert r2.permissions == 15
        assert r.permissions == 12  # original unchanged

    def test_revoke(self):
        r = Role("x", permissions=15)
        r2 = r.revoke(3)
        assert r2.permissions == 12

    def test_to_dict_from_dict(self):
        r = Role("vault", permissions=3, description="secrets")
        d = r.to_dict()
        r2 = Role.from_dict(d)
        assert r2.name == r.name
        assert r2.permissions == r.permissions
        assert r2.description == r.description

    def test_str(self):
        r = Role("signer", permissions=12)
        assert "signer" in str(r)
        assert "HS--" in str(r)


class TestBuiltinRoles:
    @pytest.mark.parametrize("name,expected_perm", [
        ("root",      15),
        ("admin",     14),
        ("signer",    12),
        ("vault",      3),
        ("audit",      9),
        ("encryptor", 10),
        ("verifier",   8),
        ("none",       0),
    ])
    def test_builtin(self, name, expected_perm):
        r = builtin_role(name)
        assert r.permissions == expected_perm
        assert r.name == name

    def test_builtin_returns_copy(self):
        r1 = builtin_role("signer")
        r2 = builtin_role("signer")
        assert r1 is not r2

    def test_unknown_builtin(self):
        with pytest.raises(HSEDValidationError):
            builtin_role("nonexistent")


# ===========================================================================
# Policy
# ===========================================================================

class TestPolicy:
    def _simple_policy(self):
        p = Policy("test")
        p.add_role(Role("signer", permissions=12))
        p.add_role(Role("vault", permissions=3))
        return p

    def test_add_and_get(self):
        p = self._simple_policy()
        r = p.get_role("signer")
        assert r.permissions == 12

    def test_missing_role(self):
        p = Policy("x")
        with pytest.raises(RoleNotFoundError):
            p.get_role("nonexistent")

    def test_conflict(self):
        p = Policy("x")
        p.add_role(Role("signer", permissions=12))
        with pytest.raises(RoleConflictError):
            p.add_role(Role("signer", permissions=8))

    def test_overwrite(self):
        p = Policy("x")
        p.add_role(Role("signer", permissions=12))
        p.add_role(Role("signer", permissions=8), overwrite=True)
        assert p.get_role("signer").permissions == 8

    def test_remove(self):
        p = self._simple_policy()
        p.remove_role("signer")
        assert not p.has_role("signer")

    def test_enforce_pass(self):
        p = self._simple_policy()
        p.enforce(role="signer", bit=Bit.SIGN)  # no exception

    def test_enforce_fail(self):
        p = self._simple_policy()
        with pytest.raises(HSEDPermissionError):
            p.enforce(role="signer", bit=Bit.DECRYPT)

    def test_add_builtin(self):
        p = Policy("x")
        r = p.add_builtin("vault")
        assert r.permissions == 3
        assert p.has_role("vault")

    def test_len_contains(self):
        p = self._simple_policy()
        assert len(p) == 2
        assert "signer" in p
        assert "nobody" not in p

    def test_serialisation_roundtrip(self):
        p = self._simple_policy()
        j = p.to_json()
        p2 = Policy.from_json(j)
        assert p2.name == p.name
        assert p2.get_role("signer").permissions == 12
        assert p2.get_role("vault").permissions == 3

    def test_save_load(self):
        p = self._simple_policy()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.hsed"
            p.save(str(path))
            p2 = Policy.load(str(path))
        assert p2.get_role("signer").permissions == 12

    def test_validate_clean(self):
        p = self._simple_policy()
        assert p.validate() == []

    def test_validate_zero_perm(self):
        p = Policy("x")
        p.add_role(Role("ghost", permissions=0))
        warnings = p.validate()
        assert any("ghost" in w for w in warnings)

    def test_validate_duplicate_mask(self):
        p = Policy("x")
        p.add_role(Role("a", permissions=12))
        p.add_role(Role("b", permissions=12))
        warnings = p.validate()
        assert any("identical" in w.lower() for w in warnings)


# ===========================================================================
# Enforcement decorator
# ===========================================================================

class TestEnforceDecorator:
    def test_allow(self):
        signer = Role("signer", permissions=12)

        @enforce(role=signer, requires=Bit.SIGN)
        def sign(data: bytes) -> bytes:
            return b"signed:" + data

        result = sign(b"hello")
        assert result == b"signed:hello"

    def test_deny_eager(self):
        signer = Role("signer", permissions=12)
        with pytest.raises(HSEDPermissionError):
            @enforce(role=signer, requires=Bit.DECRYPT)
            def decrypt(ct: bytes) -> bytes:
                return ct

    def test_deny_lazy(self):
        signer = Role("signer", permissions=12)

        @enforce(role=signer, requires=Bit.DECRYPT, eager=False)
        def decrypt(ct: bytes) -> bytes:
            return ct

        with pytest.raises(HSEDPermissionError):
            decrypt(b"x")

    def test_metadata_attached(self):
        signer = Role("signer", permissions=12)

        @enforce(role=signer, requires=Bit.HASH)
        def hash_data(data: bytes) -> str:
            return data.hex()

        assert hasattr(hash_data, "_hsed_role")
        assert hash_data._hsed_role is signer
        assert hash_data._hsed_requires == Bit.HASH

    def test_bad_role_type(self):
        with pytest.raises(HSEDValidationError):
            @enforce(role="signer", requires=Bit.SIGN)  # type: ignore
            def fn():
                pass

    def test_bad_bit_type(self):
        r = Role("x", permissions=15)
        with pytest.raises(HSEDValidationError):
            @enforce(role=r, requires=8)  # type: ignore
            def fn():
                pass


class TestPolicyEnforceOp:
    def test_allow(self):
        p = Policy("ci")
        p.add_role(Role("signer", permissions=12))

        @p.enforce_op(role="signer", requires=Bit.SIGN)
        def sign(data: bytes) -> bytes:
            return b"sig:" + data

        assert sign(b"x") == b"sig:x"

    def test_deny(self):
        p = Policy("ci")
        p.add_role(Role("signer", permissions=12))
        with pytest.raises(HSEDPermissionError):
            @p.enforce_op(role="signer", requires=Bit.DECRYPT)
            def decrypt(ct: bytes) -> bytes:
                return ct


# ===========================================================================
# PermissionScope
# ===========================================================================

class TestPermissionScope:
    def test_add_bit(self):
        r = Role("signer", permissions=12)
        assert r.can(Bit.DECRYPT) is False
        with PermissionScope(r, add=Bit.DECRYPT) as scoped:
            assert scoped.can(Bit.DECRYPT) is True
        assert r.can(Bit.DECRYPT) is False

    def test_remove_bit(self):
        r = Role("root", permissions=15)
        with PermissionScope(r, remove=Bit.DECRYPT):
            assert r.can(Bit.DECRYPT) is False
        assert r.can(Bit.DECRYPT) is True

    def test_restored_on_exception(self):
        r = Role("signer", permissions=12)
        try:
            with PermissionScope(r, add=Bit.DECRYPT):
                raise RuntimeError("test")
        except RuntimeError:
            pass
        assert r.permissions == 12


# ===========================================================================
# AWS KMS integration
# ===========================================================================

class TestAWSKMSGenerator:
    def _policy(self):
        p = Policy("ci")
        p.add_role(Role("signer", permissions=12))
        p.add_role(Role("vault", permissions=3))
        return p

    def test_generates_sign_action(self):
        from hsed.integrations.aws_kms import AWSKMSGenerator
        gen = AWSKMSGenerator(self._policy())
        doc = gen.generate(role="signer", key_arn="arn:aws:kms:us-east-1:123:key/x")
        j = doc.to_json()
        assert "kms:Sign" in j

    def test_no_decrypt_for_signer(self):
        from hsed.integrations.aws_kms import AWSKMSGenerator
        gen = AWSKMSGenerator(self._policy())
        doc = gen.generate(role="signer", key_arn="arn:aws:kms:us-east-1:123:key/x")
        # Decrypt should NOT appear in Allow, only possibly in Deny
        allow_stmts = [s for s in doc.statements if s.effect == "Allow"]
        allow_actions = [a for s in allow_stmts for a in s.actions]
        assert "kms:Decrypt" not in allow_actions

    def test_deny_statement_present(self):
        from hsed.integrations.aws_kms import AWSKMSGenerator
        gen = AWSKMSGenerator(self._policy())
        doc = gen.generate(role="signer", key_arn="arn:aws:kms:us-east-1:123:key/x")
        deny_stmts = [s for s in doc.statements if s.effect == "Deny"]
        assert len(deny_stmts) == 1

    def test_no_deny_when_disabled(self):
        from hsed.integrations.aws_kms import AWSKMSGenerator
        gen = AWSKMSGenerator(self._policy(), include_deny_statement=False)
        doc = gen.generate(role="signer", key_arn="arn:aws:kms:us-east-1:123:key/x")
        deny_stmts = [s for s in doc.statements if s.effect == "Deny"]
        assert len(deny_stmts) == 0

    def test_metadata(self):
        from hsed.integrations.aws_kms import AWSKMSGenerator
        gen = AWSKMSGenerator(self._policy())
        doc = gen.generate(role="signer", key_arn="arn:aws:kms:us-east-1:123:key/x")
        m = doc.metadata()
        assert m["hsed_role"] == "signer"
        assert m["hsed_permissions"] == 12

    def test_generate_all(self):
        from hsed.integrations.aws_kms import AWSKMSGenerator
        gen = AWSKMSGenerator(self._policy())
        docs = gen.generate_all(key_arn="arn:aws:kms:us-east-1:123:key/x")
        assert "signer" in docs
        assert "vault" in docs

    def test_vault_role_has_decrypt(self):
        from hsed.integrations.aws_kms import AWSKMSGenerator
        gen = AWSKMSGenerator(self._policy())
        doc = gen.generate(role="vault", key_arn="arn:aws:kms:us-east-1:123:key/x")
        j = doc.to_json()
        assert "kms:Decrypt" in j

    def test_valid_json(self):
        from hsed.integrations.aws_kms import AWSKMSGenerator
        gen = AWSKMSGenerator(self._policy())
        doc = gen.generate(role="signer", key_arn="arn:aws:kms:us-east-1:123:key/x")
        parsed = json.loads(doc.to_json())
        assert parsed["Version"] == "2012-10-17"
        assert "Statement" in parsed


# ===========================================================================
# Vault integration
# ===========================================================================

class TestVaultGenerator:
    def _policy(self):
        p = Policy("ci")
        p.add_role(Role("signer", permissions=12))
        return p

    def test_generates_sign_path(self):
        from hsed.integrations.vault import VaultGenerator
        gen = VaultGenerator(self._policy())
        doc = gen.generate(role="signer", mount="transit", key_name="ci-key")
        hcl = doc.to_hcl()
        assert "transit/sign/ci-key" in hcl

    def test_no_decrypt_path_for_signer(self):
        from hsed.integrations.vault import VaultGenerator
        gen = VaultGenerator(self._policy())
        doc = gen.generate(role="signer", mount="transit", key_name="ci-key")
        hcl = doc.to_hcl()
        assert "decrypt" not in hcl

    def test_hcl_contains_capabilities(self):
        from hsed.integrations.vault import VaultGenerator
        gen = VaultGenerator(self._policy())
        doc = gen.generate(role="signer", mount="transit", key_name="ci-key")
        hcl = doc.to_hcl()
        assert "capabilities" in hcl
        assert '"update"' in hcl


# ===========================================================================
# Edge cases / integration
# ===========================================================================

class TestEdgeCases:
    def test_zero_permission_role(self):
        r = Role("none", permissions=0)
        assert r.bits == []
        assert r.label == "----"
        for bit in [Bit.HASH, Bit.SIGN, Bit.ENCRYPT, Bit.DECRYPT]:
            assert r.can(bit) is False

    def test_full_permission_role(self):
        r = builtin_role("root")
        for bit in [Bit.HASH, Bit.SIGN, Bit.ENCRYPT, Bit.DECRYPT]:
            assert r.can(bit) is True

    def test_permission_string_roundtrip(self):
        for v in range(16):
            label = permission_string(v)
            assert parse_permission_string(label) == v

    def test_policy_invalid_json(self):
        with pytest.raises(HSEDValidationError):
            Policy.from_json("{invalid json")

    def test_policy_load_missing_file(self):
        with pytest.raises(FileNotFoundError):
            Policy.load("/tmp/this_file_does_not_exist_hsed_test.hsed")
