# tricard
Malware sandboxes fingerprinting

<img src="https://github.com/therealunicornsecurity/tricard/blob/main/img/tricard.jpg?raw=true" width="400" height="400">


### Glossary

__IoC__: Indicator of compromise  
__IoD__: Indicator of detection

tricard is an IoD collection and analysis toolset

### How it works

<img src="https://github.com/therealunicornsecurity/tricard/blob/main/img/tricard_graph.jpg?raw=true" width="600" height="600">

tricard works using the following steps:

- Compile unique binaries, watermarked in order to track the source of the data collected
- Send binaries to various platforms and sandboxes
- Collect data
- Analyze offline



Installation
======

### Agent and dispatcher



```bash
apt get install gcc-mingw-w64 zlib1g-dev
```

Run the dispatcher to compile as many versions of tricard as you wish:

```bash
python dispatcher.py -d your_collect_server_domain -l sample1 sample2 sample3 ....
```

All the sources are in *tmpsrc*. The *tmpbuild* folder will then contain:

- tricard.sample1.exe
- tricard.sample2.exe
- tricard.sample3.exe

*Note*

The dispatcher is meant to run on Linux, but it can be executed on Windows hosts using Python 3. However, it is necessary to:

* Install Mingw or Cygwin (for sed)
* Change dispatcher.py to use a Windows based compiler

### Server setup

You will need:

- a VPS with python3
- a domain pointing to the VPS
- SSL certificates

Change srv.py to make it use your certificates:

```python
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=443,
        debug=False,
        ssl_context=(
            "path/to/your/fullchain.pem",
            "path/to/your/privkey.pem",
        ),
    )

```

Install necessary packages:

```bash
pip install flask pandas
```

Run the server using:

```bash
python3 srv.py
```

Limitations
======

- tricard only targets x64 Windows sandboxes, although it is very easy to adapt it to support x86
- for remote dispatch, only virustotal through msf-virustotal is supported

Goals
======

tricard was initially developped in order to help us during red team engagements, but it could also be used by sandboxes editors, in order to improve their setups, and make detection less predicatble. Considering the scope of the tool, it is necessary to add that **we do not condone, under no circumstances, the use of tricard, and open source security tools in general, outside of the scope of legitimate engagements**. These tools are aimed to help security professionals in their jobs. 
