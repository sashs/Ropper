from setuptools import setup, find_packages


version = '1.8.7'
package_name = "ropper"
package_dir = "ropper"
package_description = """
With ropper you can show information about files in different file formats
and you can find gadgets to build rop chains for different architectures.
""".strip()

packages = find_packages()
valid_packages = []
for p in packages:
    if p.startswith('ropper'):
        valid_packages.append(p)

setup(
    name=package_name,
    version=version,
    description=package_description,
    packages=valid_packages,
    license="GPLv2",
    author="Sascha Schirra",
    author_email="sashs@scoding.de",
    install_requires=['capstone','filebytes>=0.9.9'],
    url="http://scoding.de/ropper/",
    scripts=['script/ropper'],
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python',
        'Intended Audience :: Developers'
    ]
)
