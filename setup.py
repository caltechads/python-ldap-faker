from setuptools import setup, find_packages

with open("README.md", "r", encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name="python-ldap-faker",
    version="1.1.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={'ldap_faker': ["py.typed"]},
    install_requires=[
        'python-ldap',
        'case-insensitive-dictionary',
        'ldap-filter'
    ],
    author="Caltech IMSS ADS",
    author_email="cmalek@caltech.edu",
    url="https://github.com/caltechads/python-ldap-faker",
    description="Fake python-ldap functions, objects and methods for use in testing.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=['ldap'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Software Development :: Testing',
    ],
)
