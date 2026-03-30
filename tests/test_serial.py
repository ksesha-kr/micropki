import pytest
from micropki.serial import SerialGenerator, validate_serial_hex


def test_generate_serial():
    generator = SerialGenerator()
    serial1 = generator.generate_serial()
    serial2 = generator.generate_serial()

    assert serial1 > 0
    assert serial2 > 0
    assert serial1 != serial2


def test_generate_serial_hex():
    generator = SerialGenerator()
    hex1 = generator.generate_serial_hex()
    hex2 = generator.generate_serial_hex()

    assert isinstance(hex1, str)
    assert isinstance(hex2, str)
    assert hex1 != hex2
    assert len(hex1) >= 8


def test_validate_serial_hex():
    assert validate_serial_hex('1A2B3C') is True
    assert validate_serial_hex('1234567890ABCDEF') is True
    assert validate_serial_hex('XYZ123') is False
    assert validate_serial_hex('') is False


def test_serial_uniqueness():
    generator = SerialGenerator()
    serials = set()

    for _ in range(100):
        serial = generator.generate_serial()
        assert serial not in serials
        serials.add(serial)