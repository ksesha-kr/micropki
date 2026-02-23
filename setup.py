from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="micropki",
    version="0.1.0",
    author="MicroPKI Team",
    author_email="info@micropki.example.com",
    description="A minimal Public Key Infrastructure (PKI) implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/micropki/micropki",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "Intended Audience :: Developers",
        "License :: Free For Educational Use",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "micropki=micropki.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)