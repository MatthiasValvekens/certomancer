from setuptools import setup
from os import path

BASE_DIR = path.abspath(path.dirname(__file__))
with open(path.join(BASE_DIR, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


# based on https://packaging.python.org/guides/single-sourcing-package-version/
def get_version():
    version_file = path.join(BASE_DIR, 'certomancer', 'version.py')
    with open(version_file, encoding='utf-8') as f:
        for line in f:
            if line.startswith('__version__'):
                delim = '"' if '"' in line else "'"
                return line.split(delim)[1]
        raise RuntimeError("Unable to find version string.")


setup(
    name='certomancer',
    version=get_version(),
    packages=['certomancer', 'certomancer.integrations'],
    url='https://github.com/MatthiasValvekens/certomancer',
    license='MIT',
    author='Matthias Valvekens',
    author_email='dev@mvalvekens.be',
    description='PKI testing tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    package_data={'certomancer.integrations': ['animator_templates/*.html']},
    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',

        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    entry_points={
        "console_scripts": [
            "certomancer = certomancer.__main__:launch"
        ]
    },
    install_requires=[
        'asn1crypto>=1.4.0',
        'click>=7.1.2',
        'oscrypto>=1.2.1',
        'pyyaml>=5.4.1',
        'python-dateutil>=2.8.1',
        'tzlocal>=2.1'
    ],
    setup_requires=[
        'wheel', 'pytest-runner'
    ],
    extras_require={
        'requests-mocker': ['requests-mock>=1.8.0'],
        'web-api': ['Werkzeug>=1.0.1', 'Jinja2>=2.11.3'],
        'pkcs12': ['cryptography>=3.4.7']
    },
    tests_require=[
        'pytest>=6.1.1', 'pytz>=2020.1',
        'freezegun>=1.1.0', 'pyhanko-certvalidator==0.17.4',
        'requests>=2.0.0', 'pytest-aiohttp>=0.3.0'
    ],
    keywords="pki testing"
)
