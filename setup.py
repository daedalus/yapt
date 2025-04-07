from setuptools import setup, find_packages

setup(
    name="yapt",
    version="0.1.0",
    description="A highly obfuscated reverse shell shellcode generator",
    author="Dario Clavijo",
    author_email="dclavijo@gmail.com",
    packages=find_packages(),
    install_requires=[line.strip() for line in open("requirements.txt")],
    entry_points={
        'console_scripts': [
            'yapt=src.main:main',
        ],
    },
)
