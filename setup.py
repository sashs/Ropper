#!/usr/bin/env python

from setuptools import setup, find_packages

version = "1.0.1"
package_name = "ropper"
package_dir = "ropper"
package_description = """
With ropper you can show informations about files in different file formats
and you can search gadgets to build rop chains for different architectures.
""".strip()

setup(
    name=package_name,
    version=version,
    description=package_description,
    packages=find_packages(),
    license="GPLv2",
    author="Sascha Schirra",
    author_email="schirra@scoding.de",
    install_requires=['capstone'],
    url="https://github.com/sashs/ropper",
    scripts=['script/ropper'],
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers'
    ]
)
