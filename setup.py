"""Setup script for Shinobi."""
from setuptools import setup, find_packages

with open("README_V1.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name='shinobi-scan',
    version='1.1.0',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'shinobi': ['assets/*.png'],
    },
    data_files=[
        ('patterns', [
            'patterns/secrets.json',
            'patterns/defaults.json',
            'patterns/ai_risks.json',
        ]),
    ],
    entry_points={
        'console_scripts': [
            'shinobi=shinobi.cli:main',
            'shinobi-scan=shinobi.cli:main',
        ],
    },
    install_requires=[
        'Pillow>=9.0',
        'gitpython>=3.1',
        'requests>=2.28',
    ],
    python_requires='>=3.10',
)
