from setuptools import setup

setup(name='debrootstrap',
      version='0.1.2',
      description='',
      author='Michael Peick',
      author_email='michael.peick+debrootstrap@gmail.com',
      url='',
      pymodules=['debrootstrap'],
      entry_points={
          'console_scripts': [
              'debrootstrap = debrootstrap:main'
          ]
      }
    )
