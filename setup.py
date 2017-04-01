from distutils.core import setup

setup(
    name='rivercrypt',
    packages=['rivercrypt'],
    version='v0.3.1',
    description='Unix style utility for asymmetrically encrypting and decrypting files in a shell pipeline',
    author='Blake Rainwater',
    author_email='rainwaterblake@gmail.com',
    url='https://github.com/brainwater/rivercrypt',
    #download_url = 'https://github.com/brainwater/rivercrypt/tarball/v0.3.1',
    keywords=['encryption'],
    classifiers=[],
    install_requires=['libnacl', 'simpleubjson', 'py-ubjson'],
)
