# MiniSOC sample dataset

This directory documents the sample-data boundary for the prototype. The
dataset is generated, not collected from a host or a real service.

Generate the mixed sample dataset:

```text
python src/minisoc/attack_simulator.py --seed 20261015 --output samples/mixed.log
```

The generated file contains normal traffic plus synthetic brute-force,
synthetic port-scan, SQL-injection, and path-traversal events. The addresses
are reserved documentation ranges. Do not replace this sample with live logs.

The `normal` scenario is generated through the Python workflow and is used by
the test suite to prove that 1,000 normal synthetic lines produce zero alerts.
