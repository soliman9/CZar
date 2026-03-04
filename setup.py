from setuptools import setup, find_packages

setup(
    name="CZar",
    version="3.0.0",
    description="A lightweight secure CLI password manager",
    author="Ahmed Soliman",
    url="https://github.com/soliman9/CZar",
    license="MIT",
    python_requires=">=3.7",
    packages=find_packages(exclude=["test*", "*.test"]),
    entry_points={
        'console_scripts': [
            'czar=startCzar:main',
        ],
    },
    install_requires=[
        "pyperclip==1.8.2",
        "cryptography==46.0.5",
        "maskpass==0.3.7",
        "tabulate==0.9.0",
        "more-itertools==10.1.0",
        "argon2-cffi==23.1.0",
    ],
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Office/Business",
        "Topic :: Security",
    ],
    keywords="password manager encryption security cli",
)
