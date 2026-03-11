from setuptools import setup, find_packages

setup(
    name="apkshield",
    version="2.1.0",
    description="Professional Android APK Security Scanner",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "androguard>=4.0.0",
        "reportlab>=4.0.0",
        "pyOpenSSL>=24.0.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "black", "ruff"],
    },
     entry_points={
        "console_scripts": ["apkshield=apkshield.__main__:main"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
    ],
    license="MIT",
)
