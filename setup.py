from setuptools import setup, find_packages


version = '1.11.13'
package_name = "ropper"
package_dir = "ropper"
package_description = """Show information about files in different file formats and find gadgets to build rop chains for different architectures.
""".strip()

packages = find_packages()
valid_packages = []
for p in packages:
    if p.startswith('ropper'):
        valid_packages.append(p)

install_requires = ['filebytes>=0.9.18']
try:
    import capstone
    if capstone.cs_version()[0] < 3:
        install_requires.append('capstone')
    del capstone
except:
    install_requires.append('capstone')

setup(
    name=package_name,
    version=version,
    description=package_description,
    packages=valid_packages,
    license="BSD",
    author="Sascha Schirra",
    author_email="sashs@scoding.de",
    install_requires=install_requires,
    url="http://scoding.de/ropper/",
    entry_points={'console_scripts': ['ropper = ropper.__main__:main']},
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Intended Audience :: Developers'
    ]
)
