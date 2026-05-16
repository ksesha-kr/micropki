import pytest
from micropki.policy import PolicyEnforcer, PolicyViolation


def test_key_size_enforcement():
    policy = PolicyEnforcer()
    with pytest.raises(PolicyViolation):
        policy.check_key_size(1024, 'rsa', 'end_entity')

def test_validity_enforcement():
    policy = PolicyEnforcer()
    with pytest.raises(PolicyViolation):
        policy.check_validity(400, 'end_entity')

def test_san_validation():
    policy = PolicyEnforcer()
    with pytest.raises(PolicyViolation):
        policy.check_san_types(['email:test@example.com'], 'server')

def test_wildcard_rejection():
    policy = PolicyEnforcer()
    with pytest.raises(PolicyViolation):
        policy.check_san_types(['dns:*.example.com'], 'server')