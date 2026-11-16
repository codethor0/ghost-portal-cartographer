"""Reproducible synthetic example; prints the entire stable JSON result."""
import json
from pathlib import Path

from gpc import Query, from_json_dict


def main():
    fixture = json.loads((Path(__file__).parent / 'synthetic_example.json').read_text(encoding='utf-8'))
    model = from_json_dict(fixture)
    finding = model.analyze(Query(**fixture['query']))
    print(json.dumps(finding.to_dict(), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
