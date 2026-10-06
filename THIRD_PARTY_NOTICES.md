# Third-party notices

att-monitor ships data and code from the following projects, under their licences.

## World map: world-atlas (ISC licence), from Natural Earth (public domain)

`internal/web/static/world.json`, the Network page's world map, is made by `scripts/worldmap/make_world.py`
from `countries-110m.json` of [world-atlas](https://github.com/topojson/world-atlas) 2.0.2, which packages
the 1:110m Admin 0 country outlines of [Natural Earth](https://www.naturalearthdata.com) v4.1.0. Natural
Earth's data are in the public domain. world-atlas is distributed under this licence (the same notice is
embedded in `world.json`, and so in every program that carries the map):

```
Copyright 2013-2019 Michael Bostock

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.
```

## IP address database: IPtoASN (public domain, PDDL 1.0)

The Network page's IP database is not shipped: the service downloads the IPtoASN tables
(<https://iptoasn.com>) at run time, or uses copies placed in the data directory by hand. They are
made available under the Open Data Commons Public Domain Dedication and License (PDDL) 1.0.
