# JWT Toolkit (Auth)

A simple Python toolkit for generating and verifying JSON Web Tokens (JWTs) for authentication.

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)

## Overview

This library provides basic functions to generate secure JSON Web Tokens (JWTs) for user authentication and to verify their validity.

## Features

* JWT Generation with HS256 algorithm.
* JWT Verification, including expiry check.
* Simple API for easy integration.

## Installation

To use this toolkit, simply download the `jwt_helper.py` file and import the `generate_jwt` and `verify_jwt` functions into your Python project.

## Basic Usage

```python
from jwt_helper import generate_jwt, verify_jwt
import time

secret_key = "your_secret_key"
user_data = {'user_id': 123}
token = generate_jwt(user_data, secret_key)
print("Generated JWT:", token)

is_valid, payload = verify_jwt(token, secret_key)
if is_valid:
    print("Token is valid. Payload:", payload)
else:
    print("Token is invalid:", payload)
