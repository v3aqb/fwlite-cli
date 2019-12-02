
from setuptools import setup

setup(
    name="fwlite-cli",
    version="0.2",
    license='GPLv3',
    description="A anti-censorship HTTP proxy with builtin shadowsocks support",
    author='v3aqb',
    author_email='null',
    url='https://github.com/v3aqb/fwlite-cli',
    packages=['fwlite_cli'],
    package_data={
        'fwlite-cli': ['README.rst', 'LICENSE']
    },
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'fwlite-cli = fwlite_cli.__main__:main'
        ]
    },
    dependency_links=['https://github.com/v3aqb/hxcrypto/archive/master.zip#egg=hxcrypto-0.0.3'],
    install_requires=["hxcrypto", "repoze.lru", "dnslib"],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: Proxy Servers',
    ],
)
