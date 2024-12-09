from setuptools import setup, find_packages

setup(
    name="pybersec",  # Changed from package_checker
    version="0.0.1",
    packages=find_packages(),
    install_requires=[
        "requests",
        "click",
        "packaging",
        "pygithub",
        "pypistats",
    ],
    entry_points={
        "console_scripts": [
            "pybersec-check=pybersec.check_yourself:main",
            "pybersec=pybersec.cli:main",
        ],
    },
)
