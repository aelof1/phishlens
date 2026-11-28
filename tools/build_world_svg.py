"""Build phishlens/web/static/world.svg from Natural Earth country shapes (public domain).

Developer tool, not needed at runtime. Usage:

    curl -L -o ne.geojson https://cdn.jsdelivr.net/gh/nvkelso/natural-earth-vector@v5.1.2/geojson/ne_110m_admin_0_countries.geojson
    python tools/build_world_svg.py ne.geojson

Robinson projection, Antarctica left out. Each country is a <path data-cc="FR"> (ISO 3166-1 alpha-2).
"""

import json
import math
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "phishlens" / "web" / "static" / "world.svg"
WIDTH = 1000

# Robinson projection table, every 5 degrees of latitude
RX = [1.0000, 0.9986, 0.9954, 0.9900, 0.9822, 0.9730, 0.9600, 0.9427, 0.9216, 0.8962,
      0.8679, 0.8350, 0.7986, 0.7597, 0.7186, 0.6732, 0.6213, 0.5722, 0.5322]
RY = [0.0000, 0.0620, 0.1240, 0.1860, 0.2480, 0.3100, 0.3720, 0.4340, 0.4958, 0.5571,
      0.6176, 0.6769, 0.7346, 0.7903, 0.8435, 0.8936, 0.9394, 0.9761, 1.0000]


def robinson(lon: float, lat: float) -> tuple[float, float]:
    a = min(abs(lat), 89.999) / 5
    i = int(a)
    f = a - i
    x_coef = RX[i] + (RX[i + 1] - RX[i]) * f
    y_coef = RY[i] + (RY[i + 1] - RY[i]) * f
    return 0.8487 * x_coef * math.radians(lon), 1.3523 * y_coef * math.copysign(1, lat)


def country_code(props: dict) -> str | None:
    for key in ("ISO_A2", "ISO_A2_EH"):
        code = props.get(key)
        if code and code != "-99" and len(code) == 2:
            return code.upper()
    return None


def main(source: str) -> None:
    features = json.loads(Path(source).read_text(encoding="utf-8"))["features"]
    shapes = []
    for feature in features:
        props = feature["properties"]
        code = country_code(props)
        if code == "AQ":
            continue
        geom = feature["geometry"]
        polygons = geom["coordinates"] if geom["type"] == "MultiPolygon" else [geom["coordinates"]]
        rings = [[robinson(lon, lat) for lon, lat in ring] for polygon in polygons for ring in polygon]
        shapes.append((code, props.get("NAME", ""), rings))

    xs = [x for _, _, rings in shapes for ring in rings for x, _ in ring]
    ys = [y for _, _, rings in shapes for ring in rings for _, y in ring]
    scale = WIDTH / (max(xs) - min(xs))
    height = round((max(ys) - min(ys)) * scale)
    min_x, max_y = min(xs), max(ys)

    paths = []
    for code, name, rings in shapes:
        parts = []
        for ring in rings:
            points, last = [], None
            for x, y in ring:
                p = (round((x - min_x) * scale, 1), round((max_y - y) * scale, 1))
                if last is None or abs(p[0] - last[0]) + abs(p[1] - last[1]) >= 0.8:
                    points.append(p)
                    last = p
            if len(points) >= 3:
                parts.append("M" + "L".join(f"{x:g},{y:g}" for x, y in points) + "Z")
        if not parts:
            continue
        attrs = f' data-cc="{code}"' if code else ""
        title = name.replace("&", "&amp;").replace("<", "")
        paths.append(f'<path{attrs} d="{"".join(parts)}"><title>{title}</title></path>')

    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" class="world" '
           f'role="img" aria-label="World map">\n'
           f'<!-- Made with Natural Earth (public domain), Robinson projection -->\n'
           + "\n".join(paths) + "\n</svg>\n")
    OUT.write_text(svg, encoding="utf-8")
    print(f"{OUT}: {len(paths)} countries, {len(svg) // 1024} KB, {WIDTH}x{height}")


if __name__ == "__main__":
    main(sys.argv[1])
