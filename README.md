## Description

External data acquisition module for Snort which reads directly from an Endace DAG card.

## Requirements

* Endace DAG SDK (available with the purchase of an [Endace DAG](http://www.endace.com/endace-dag-high-speed-packet-capture-cards.html) card)
* [Snort DAQ libraries](http://www.snort.org/snort-downloads)

## Installation

* Compile and install Endace SDK.
* Compile and install Snort DAQ libraries. (Version 1.1 or 2.x should work.)
* Clone this repository or download and extract the [zip archive file.](https://github.com/SgtMalicious/Endace-DAQ-Module/archive/master.zip)
* Configure and compile
<pre>
    autoreconf -ivf
    ./configure
    make
    make install
</pre>
* Add the configuration items to snort.conf
<pre>
    config daq: endace
    config daq_dir: /usr/local/lib/daq
    config daq_mode: passive
</pre>

## Caveats 

* This code has been somewhat tested.

## Thanks

* Randy Caldejon at packetchaser.org for authoring the Napatech DAQ module
* Brian Trammell at Carnegie Mellon for authoring the YAF DAG code
* Endace for authoring tons of documentation
* Jason Ish for some much needed updates and corrections

## License

Copyright (c) 2018 William Allison

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
