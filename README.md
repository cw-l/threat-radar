# Threat Tracker (TT)

An interactive tracker of threat actors relevant to your organisation, so you can prioritise investment where it matters.

**Use it here: <https://threat-trac.ker.life>**

This repository holds the source and the weekly data. You don't need to clone or run anything to use TT.

> **Data notice.** Datasets are generated each week from web search and an LLM, and may contain errors or omissions. Treat them as leads to verify, not as authoritative intelligence.

## How to read the tracker

Each blip is one threat actor (TA), with a write-up of the incidents attributed to it. Its position shows where the activity sits:

| Dimension | Values | Meaning |
| --------- | ------ | ------- |
| Ring | `Singapore`, `Southeast Asia`, `Asia`, `ROTW` | Where the incidents happened, from closest to furthest. `ROTW` is rest of world. |
| Quadrant | `CIIs`, `My-Industry`, `My-Suppliers`, `All Others` | How the activity relates to you: your critical infrastructure, your industry, your suppliers, or everything else. |

An actor active in more than one ring or quadrant appears once for each combination, with only the incidents that apply to it.

## Using it

1. Choose a dataset from the dropdown and select **Run Threat Tracker**.
2. Select a quadrant button to zoom in, and hover a blip to see which actor it is.
3. Switch datasets any time with the dropdown on the tracker page. Each tracker has its own link you can share.

## Where the data comes from

A GitHub Actions job runs every Monday. It searches recent reporting, reads the articles, and uses an LLM to extract threat actors and their incidents into a CSV. Each run is kept as a dated file in [`data/`](data/), and the dropdown lists them newest first. Threat actors already reported in an earlier run are not repeated.

## Source and license

Built on [Build Your Own Radar](https://github.com/thoughtworks/build-your-own-radar) by Thoughtworks, Inc., and inspired by the [Thoughtworks Technology Radar](https://www.thoughtworks.com/radar). Released under the [AGPL-3.0](LICENSE.md). If you host a modified version, the license requires you to make your source available.

Running your own copy needs your own search and LLM API keys and a GitHub Pages setup.

Planned work is tracked in [Issues](../../issues).