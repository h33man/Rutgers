#!/usr/bin/env python3
"""
Plot legitimate throughput vs DDoS attack rate, broken down by packet size.

Reads the JSON file produced by ddos_monitor.py.  Each entry in the file has
a 'msg_size' field inside 'test_info'; the plotter groups entries by packet
size and draws one line per size on each figure.

Figures produced
----------------
1. Sender throughput   vs attack rate  (one line per packet size)
2. Receiver throughput vs attack rate  (one line per packet size)
3. Packet loss %       vs attack rate  (one line per packet size)
4. Combined subplot (all three stacked) — optional save to disk

Usage
-----
  python3 plot_ddos.py ddos_results.json
  python3 plot_ddos.py ddos_results.json -o ddos_plot.png
  python3 plot_ddos.py ddos_results.json --no-loss
  python3 plot_ddos.py ddos_results.json --no-individual
  python3 plot_ddos.py ddos_results.json --no-plot        # text summary only
"""

import json
import argparse
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from typing import List, Dict, Tuple, Optional

# ---------------------------------------------------------------------------
# Style — matches benchmark_plotter.py exactly
# ---------------------------------------------------------------------------

# Named colors from benchmark_plotter.py, one per packet size in sorted order
PALETTE = ['#87CEEB', '#DDA0DD', '#F0B6C1', '#98FB98',
           '#FFD700', '#FFA07A', '#7B68EE', '#20B2AA']

MARKERS   = ['o', 's', '^', 'D']
STD_ALPHA = 0.50   # 50 % opacity for shaded std bands

plt.rcParams.update({
    'font.size':        12,
    'axes.titlesize':   14,
    'axes.labelsize':   12,
    'xtick.labelsize':  10,
    'ytick.labelsize':  10,
    'legend.fontsize':  11,
    'figure.titlesize': 16,
})


# ---------------------------------------------------------------------------
# Loader + plotter class
# ---------------------------------------------------------------------------

class DDoSPlotter:
    def __init__(self, input_file: str):
        self.input_file = input_file
        self.datasets: List[Dict] = []

    # ------------------------------------------------------------------
    def load_data(self) -> bool:
        try:
            with open(self.input_file, 'r') as f:
                raw = f.read().strip()
        except FileNotFoundError:
            print(f"Error: '{self.input_file}' not found")
            return False

        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = [parsed]
            if not isinstance(parsed, list):
                print("Error: unexpected JSON structure")
                return False
        except json.JSONDecodeError:
            parsed = []
            for chunk in (raw.replace('}\n{', '}\nSPLIT\n{')
                             .replace('}{',   '}\nSPLIT\n{')
                             .split('SPLIT')):
                chunk = chunk.strip()
                if chunk:
                    try:
                        parsed.append(json.loads(chunk))
                    except Exception:
                        continue

        valid = []
        for i, entry in enumerate(parsed):
            ti = entry.get('test_info', {})
            if ti.get('test_type') != 'ddos_throughput':
                print(f"  Skipping entry {i+1}: not ddos_throughput "
                      f"(type={ti.get('test_type','unknown')})")
                continue
            if 'attack_rate_gbps' not in ti:
                print(f"  Skipping entry {i+1}: missing attack_rate_gbps")
                continue
            if 'bandwidth_samples' not in entry:
                print(f"  Skipping entry {i+1}: missing bandwidth_samples")
                continue
            valid.append(entry)

        if not valid:
            print("Error: no valid ddos_throughput datasets found")
            return False

        # Sort by packet size first, then attack rate
        self.datasets = sorted(valid,
                               key=lambda e: (e['test_info'].get('msg_size', 0),
                                              e['test_info']['attack_rate_gbps']))

        sizes = sorted({d['test_info'].get('msg_size', 0) for d in self.datasets})
        print(f"Loaded {len(self.datasets)} dataset(s) across "
              f"{len(sizes)} packet size(s): {sizes}")
        for ds in self.datasets:
            ti   = ds['test_info']
            stat = ds.get('statistics', {})
            rx   = stat.get('receiver', {}).get('avg_mbps', 0)
            print(f"  size={ti.get('msg_size','?'):>6} B  "
                  f"attack={ti['attack_rate_gbps']:>6.1f} Gbps  "
                  f"{len(ds['bandwidth_samples'])} samples  "
                  f"avg RX {rx:.1f} Mbps")
        return True

    # ------------------------------------------------------------------
    def _build_series(self) -> Dict[int, Dict]:
        """
        Returns
        -------
        { msg_size: {
            'rates':  np.array,
            'tx_avg': np.array,  # Mbps
            'tx_std': np.array,
            'rx_avg': np.array,
            'rx_std': np.array,
            'loss':   np.array,
          }, ...
        }
        Multiple runs with the same (msg_size, attack_rate) are merged.
        """
        raw: Dict[int, Dict[float, Dict]] = {}
        for ds in self.datasets:
            ti   = ds['test_info']
            size = int(ti.get('msg_size', 0))
            rate = float(ti['attack_rate_gbps'])
            raw.setdefault(size, {}).setdefault(
                rate, {'tx': [], 'rx': [], 'loss': []})
            bucket = raw[size][rate]
            for s in ds['bandwidth_samples']:
                bucket['tx'].append(s['sender_bandwidth_mbps'])
                bucket['rx'].append(s['receiver_bandwidth_mbps'])
                bucket['loss'].append(s['loss_percent'])

        series: Dict[int, Dict] = {}
        for size, rate_map in raw.items():
            rates = sorted(rate_map.keys())
            tx_avg, tx_std, rx_avg, rx_std, loss = [], [], [], [], []
            for r in rates:
                b = rate_map[r]
                tx_avg.append(np.mean(b['tx']));   tx_std.append(np.std(b['tx']))
                rx_avg.append(np.mean(b['rx']));   rx_std.append(np.std(b['rx']))
                loss.append(np.mean(b['loss']))
            series[size] = {
                'rates':  np.array(rates),
                'tx_avg': np.array(tx_avg), 'tx_std': np.array(tx_std),
                'rx_avg': np.array(rx_avg), 'rx_std': np.array(rx_std),
                'loss':   np.array(loss),
            }
        return series

    # ------------------------------------------------------------------
    # Axes-level drawing helpers
    # ------------------------------------------------------------------

    def _draw_throughput_bars(self, ax, s: Dict, size: int):
        """
        Overlapping bar chart matching the uploaded reference image:
          - Receiver (salmon/red) drawn first at full width
          - Sender (steel blue) drawn on top at full width with transparency
        Both bars share the same x position so the taller one peeks out
        behind the shorter one, exactly as in the reference figure.
        Error bars at 50 % opacity.
        """
        COLOR_TX = '#6B9BC3'   # muted steel-blue  (Sender / Client)
        COLOR_RX = '#E07B7B'   # muted salmon-red   (Receiver / Server)

        rates  = s['rates']
        x      = np.arange(len(rates))
        width  = 0.35

        tx_avg = s['tx_avg'] / 1000   # Mbps → Gbps
        tx_std = s['tx_std'] / 1000
        rx_avg = s['rx_avg'] / 1000
        rx_std = s['rx_std'] / 1000

        ax.bar(x - width / 2, tx_avg, width,
               yerr=tx_std, capsize=5,
               color=COLOR_TX, edgecolor='black', linewidth=0.5,
               alpha=0.8, label='Sender',
               error_kw=dict(elinewidth=1.5, ecolor='gray', alpha=STD_ALPHA))

        ax.bar(x + width / 2, rx_avg, width,
               yerr=rx_std, capsize=5,
               color=COLOR_RX, edgecolor='black', linewidth=0.5,
               alpha=0.8, label='Receiver (authenticated)',
               error_kw=dict(elinewidth=1.5, ecolor='gray', alpha=STD_ALPHA))

        ax.set_xlabel('DDoS Attack Traffic Rate (Gbps)', fontweight='bold')
        ax.set_ylabel('Throughput (Gbps)', fontweight='bold')
        ax.set_title(f'Throughput vs DDoS Attack Rate  —  {size} B packets',
                     fontweight='bold', pad=10)
        ax.set_xticks(x)
        ax.set_xticklabels([f'{r:.0f}' for r in rates])
        ax.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))
        ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5, axis='y')
        ax.set_axisbelow(True)
        ax.set_ylim(bottom=0)
        ax.legend(loc='upper right', framealpha=0.9)

    # ------------------------------------------------------------------
    def _draw_loss(self, ax, series: Dict[int, Dict]):
        """Packet-loss (%) vs attack rate, one line per packet size."""
        sizes = sorted(series.keys())
        for idx, size in enumerate(sizes):
            s     = series[size]
            color = PALETTE[idx % len(PALETTE)]
            mark  = MARKERS[idx % len(MARKERS)]

            ax.plot(s['rates'], s['loss'],
                    marker=mark, markersize=7, linewidth=2.0,
                    color=color, alpha=0.8,
                    markeredgecolor='black', markeredgewidth=0.5,
                    label=f'{size} B')

        ax.set_xlabel('DDoS Attack Traffic Rate (Gbps)', fontweight='bold')
        ax.set_ylabel('Avg Packet Loss (%)', fontweight='bold')
        ax.set_title('Packet Loss of Legitimate Traffic vs DDoS Attack Rate',
                     fontweight='bold', pad=10)
        ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.5, axis='y')
        ax.set_axisbelow(True)
        ax.set_ylim(bottom=0)
        ax.legend(title='Packet size', loc='best', framealpha=0.9)

        all_rates = sorted({r for sv in series.values() for r in sv['rates']})
        ax.set_xticks(all_rates)
        ax.set_xticklabels([f'{r:.0f}' for r in all_rates])

    # ------------------------------------------------------------------
    # Figure builders
    # ------------------------------------------------------------------

    def _fig_throughput_per_size(self, series, size: int):
        """One bar-chart figure for a single packet size (sender + receiver)."""
        fig, ax = plt.subplots(figsize=(14, 8))
        self._draw_throughput_bars(ax, series[size], size)
        plt.tight_layout()
        return fig

    def _fig_loss(self, series):
        fig, ax = plt.subplots(figsize=(14, 6))
        self._draw_loss(ax, series)
        plt.tight_layout()
        return fig

    def _fig_combined(self, series, show_loss: bool):
        sizes  = sorted(series.keys())
        n_rows = len(sizes) + (1 if show_loss else 0)
        fig, axes = plt.subplots(n_rows, 1,
                                 figsize=(14, 7 * n_rows),
                                 gridspec_kw={'hspace': 0.55})
        if n_rows == 1:
            axes = [axes]

        for i, size in enumerate(sizes):
            self._draw_throughput_bars(axes[i], series[size], size)

        if show_loss:
            self._draw_loss(axes[-1], series)

        fig.suptitle('DDoS Attack: Impact on Legitimate Traffic',
                     fontsize=16, fontweight='bold', y=0.998)
        plt.tight_layout(rect=[0, 0, 1, 0.997])
        return fig

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def plot(self, output_file: Optional[str] = None,
             show_loss: bool = True, individual: bool = True):

        series = self._build_series()
        sizes  = sorted(series.keys())

        if individual:
            for size in sizes:
                _save_and_show(self._fig_throughput_per_size(series, size),
                               output_file, f'_throughput_{size}B')
            if show_loss:
                _save_and_show(self._fig_loss(series), output_file, '_loss')

        _save_and_show(self._fig_combined(series, show_loss),
                       output_file, '_combined')

    # ------------------------------------------------------------------
    def print_summary(self):
        series = self._build_series()
        for size in sorted(series.keys()):
            s = series[size]
            print(f"\n{'='*72}")
            print(f"Packet size: {size} B")
            print(f"{'='*72}")
            print(f"{'Attack (Gbps)':>14}  {'TX avg (Mbps)':>14}  "
                  f"{'RX avg (Mbps)':>14}  {'Loss %':>8}  "
                  f"{'TX σ':>8}  {'RX σ':>8}")
            print('-' * 72)
            for i, rate in enumerate(s['rates']):
                print(f"{rate:>14.1f}  {s['tx_avg'][i]:>14.2f}  "
                      f"{s['rx_avg'][i]:>14.2f}  {s['loss'][i]:>8.2f}  "
                      f"{s['tx_std'][i]:>8.2f}  {s['rx_std'][i]:>8.2f}")
        print('=' * 72)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _split_ext(path: str) -> Tuple[str, str]:
    return tuple(path.rsplit('.', 1)) if '.' in path else (path, 'png')


def _save_and_show(fig, output_file: Optional[str], suffix: str):
    if output_file:
        base, ext = _split_ext(output_file)
        path = f"{base}{suffix}.{ext}"
        fig.savefig(path, dpi=300, bbox_inches='tight')
        print(f"Saved: {path}")
    plt.show()
    plt.close(fig)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Plot legitimate throughput vs DDoS attack rate '
                    '(one line per packet size)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 plot_ddos.py ddos_results.json
  python3 plot_ddos.py ddos_results.json -o ddos_plot.png
  python3 plot_ddos.py ddos_results.json --no-loss
  python3 plot_ddos.py ddos_results.json --no-individual
  python3 plot_ddos.py ddos_results.json --no-plot
        """
    )
    parser.add_argument('input',
                        help='JSON file produced by ddos_monitor.py')
    parser.add_argument('-o', '--output', default=None,
                        help='Output filename (e.g. ddos_plot.png); '
                             '_sender/_receiver/_loss/_combined are appended')
    parser.add_argument('--no-plot',       action='store_true',
                        help='Print text summary only; do not display plots')
    parser.add_argument('--no-loss',       action='store_true',
                        help='Omit the packet-loss figure')
    parser.add_argument('--no-individual', action='store_true',
                        help='Skip individual figures; only produce combined subplot')

    args = parser.parse_args()

    plotter = DDoSPlotter(args.input)
    if not plotter.load_data():
        return

    plotter.print_summary()

    if not args.no_plot:
        plotter.plot(
            output_file=args.output,
            show_loss=not args.no_loss,
            individual=not args.no_individual,
        )


if __name__ == '__main__':
    main()
