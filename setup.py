from setuptools import setup, find_packages

with open("requirements.txt") as f:
    install_requires = f.read().strip().split("\n")

setup(
    name="passkey_auth",
    version="1.0.0",
    description="Production-ready WebAuthn/Passkey authentication for Frappe/ERPNext",
    author="UCSC",
    author_email="admin@ucsc.cmb.ac.lk",
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    install_requires=install_requires,
)
