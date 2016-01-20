from setuptools import setup

setup(name='debrootstrap',
      version='0.1.3',
      description='',
      author='Michael Peick',
      author_email='michael.peick+debrootstrap@gmail.com',
      url='https://github.com/peick/debrootstrap',
      pymodules=['debrootstrap'],
      entry_points={
          'console_scripts': [
              'debrootstrap = debrootstrap:main'
          ]
      }
    )
