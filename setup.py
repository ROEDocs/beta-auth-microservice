"""
FastAPI Google OAuth Example - Package Setup

This module defines the package setup configuration for the FastAPI authentication server.
It specifies package metadata, dependencies, and included packages for distribution.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

from setuptools import setup, find_packages

setup(
    name="fastapi-auth-server",
    version="0.2.0",
    description="Production-ready FastAPI authentication server with Google OAuth and JWT.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="James Fincher",
    author_email="example@example.com",  # Replace with actual email if appropriate
    url="https://github.com/seandavi/fastapi-google-oauth-example",
    packages=find_packages(include=["app", "app.*"]),
    python_requires=">=3.11",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
)
