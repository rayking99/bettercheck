from setuptools import setup, find_packages

setup(
    name="package_checker",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "click",
        "safety",
        "packaging",
        "pygithub",
        "pypistats",
    ],
    entry_points={
        "console_scripts": [
            "package-checker=package_checker.cli:main",
        ],
    },
)
