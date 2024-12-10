from setuptools import setup, find_packages

setup(
    name="bettercheck",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "requests",
        "click",
        "aiohttp",
        "PyGithub",
        "jsonschema",
        "packaging",
    ],
    extras_require={
        "dev": [
            "pytest>=8.2.0",
            "pytest-asyncio>=0.24.0",
            "pytest-cov",
            "pytest-mock",
        ]
    },
)
