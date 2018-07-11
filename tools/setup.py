# Setup module for Sigma toolchain
# derived from example at https://github.com/pypa/sampleproject/blob/master/setup.py
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='sigmatools',
    version='0.5',
    description='Tools for the Generic Signature Format for SIEM Systems',
    long_description=long_description,
    url='https://github.com/Neo23x0/sigma',
    author='Sigma Project',
    author_email='thomas@patzke.org',
    license='LGPLv3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Topic :: Internet :: Log Analysis',
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Environment :: Console',
    ],
    keywords='security monitoring siem logging signatures elasticsearch splunk ids sysmon',
    packages=['sigma'],
    python_requires='~=3.5',
    install_requires=['PyYAML'],
    extras_require={
        'test': ['coverage', 'yamllint'],
    },
    data_files=[
        ('etc/sigma', [
            'config/arcsight.yml',
            'config/elk-defaultindex-filebeat.yml',
            'config/elk-defaultindex-logstash.yml',
            'config/elk-defaultindex.yml',
            'config/elk-linux.yml',
            'config/elk-windows.yml',
            'config/helk.yml',
            'config/logpoint-windows-all.yml',
            'config/qualys.yml',
            'config/spark.yml',
            'config/splunk-windows-all.yml',
        ])],
    scripts=[
        'sigmac',
        'merge_sigma'
        ]
)
