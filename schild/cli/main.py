import argparse
import os
import sys

# Load .env
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except ImportError:
    pass


def main():
    parser = argparse.ArgumentParser(
        prog="schild",
        description="SCHILD — Autonomous Defense & AI-Driven Threat Hunting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Defense Modes:
  observe    Log-only, no automated actions
  hunt       Proactive hunting, no auto-remediation (default)
  contain    Auto-isolate threats, confirm kills
  eliminate  Fully autonomous response (use with caution)

AI Providers:
  openai     OpenAI GPT (requires OPENAI_API_KEY)
  anthropic  Anthropic Claude (requires ANTHROPIC_API_KEY)
  gemini     Google Gemini (requires GEMINI_API_KEY)
  ollama     Ollama local LLM (requires ollama serve)

Examples:
  schild                              # Start interactive CLI
  schild --serve                      # Start REST API backend
  schild --serve --api-port 9000      # Custom API port
  schild --mode contain               # Start in contain mode
  schild --provider ollama            # Use local Ollama
  schild --hunt                       # Run threat hunt and exit
        """,
    )

    parser.add_argument(
        "--mode", "-m",
        choices=["observe", "hunt", "contain", "eliminate"],
        default=os.getenv("SCHILD_DEFENSE_MODE", "hunt"),
        help="Defense mode (default: hunt)",
    )
    parser.add_argument(
        "--provider", "-p",
        choices=["openai", "anthropic", "gemini", "ollama"],
        default=os.getenv("SCHILD_AI_PROVIDER", "openai"),
        help="AI provider (default: openai)",
    )
    parser.add_argument(
        "--db", default=os.getenv("SCHILD_DB_PATH", "schild_memory.db"),
        help="Database path",
    )
    parser.add_argument(
        "--hunt", action="store_true",
        help="Run all hunt hypotheses and exit",
    )
    parser.add_argument(
        "--hunt-id", metavar="ID",
        help="Run specific hunt hypothesis (e.g., H-001)",
    )
    parser.add_argument(
        "--zeroday", action="store_true",
        help="Run zero-day behavioral scan and exit",
    )
    parser.add_argument(
        "--anomaly", action="store_true",
        help="Run anomaly detection and exit",
    )
    parser.add_argument(
        "--baseline", action="store_true",
        help="Build behavioral baseline and exit",
    )
    parser.add_argument(
        "--baseline-samples", type=int, default=20,
        help="Number of baseline samples to collect (default: 20)",
    )
    parser.add_argument(
        "--ml-train", action="store_true",
        help="Train all ML anomaly models and exit",
    )
    parser.add_argument(
        "--ml-retrain", action="store_true",
        help="Retrain all ML models from scratch and exit",
    )
    parser.add_argument(
        "--ml-update", action="store_true",
        help="Incrementally update ML models and exit",
    )
    parser.add_argument(
        "--enrich", nargs=2, metavar=("TYPE", "VALUE"),
        help="Enrich an IOC: --enrich ip 1.2.3.4",
    )
    # DONE: TASK-07
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Backup the SCHILD database and exit",
    )
    parser.add_argument(
        "--backup-dir",
        default="schild_backups",
        help="Directory to store backups (default: schild_backups)",
    )
    # DONE: TASK-08
    parser.add_argument(
        "--syslog", action="store_true",
        help="Start UDP syslog receiver on port 5140",
    )
    parser.add_argument(
        "--syslog-port", type=int, default=5140,
        help="Syslog UDP port (default: 5140)",
    )
    parser.add_argument(
        "--watch-log", metavar="PATH", action="append",
        help="Watch a log file for new entries (repeatable)",
    )
    # DONE: TASK-09
    parser.add_argument(
        "--schedule",
        type=int,
        metavar="MINUTES",
        help="Run threat hunt every N minutes in background (e.g. --schedule 360)",
    )
    parser.add_argument(
        "--version", action="version", version="SCHILD 1.1.0",  # DONE: TASK-06
    )
    # DONE: TASK-11.8
    parser.add_argument(
        "--sidecar",
        metavar="NAME=URL",
        action="append",
        help=(
            "Register a remote sidecar. Format: name=http://host:port. "
            "Dapat diulang untuk beberapa host. "
            "Contoh: --sidecar dvwa=http://10.0.0.5:8421"
        ),
    )
    parser.add_argument(
        "--sidecar-secret",
        default=os.environ.get("SCHILD_SIDECAR_SECRET", ""),
        help="Shared secret untuk sidecar auth (atau set SCHILD_SIDECAR_SECRET env var)",
    )
    parser.add_argument(
        "--ping-sidecars",
        action="store_true",
        help="Ping semua registered sidecar dan exit",
    )
    parser.add_argument(
        "prompt", nargs="*",
        help="Optional prompt to ask the AI directly",
    )
    # REST API backend
    parser.add_argument(
        "--serve", action="store_true",
        help="Start REST API backend instead of interactive CLI",
    )
    parser.add_argument(
        "--api-host",
        default=os.getenv("SCHILD_API_HOST", "0.0.0.0"),
        help="API server bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=int(os.getenv("SCHILD_API_PORT", "8420")),
        help="API server port (default: 8420)",
    )

    args = parser.parse_args()

    # Import here to allow --version without deps
    from schild.core.config import DefenseMode, AIProvider, COLORS

    # ── REST API mode: early exit, server manages its own agent ──────────
    if args.serve:
        from schild.api.server import run_server
        print(f"\033[32m  Starting SCHILD API backend on "
              f"{args.api_host}:{args.api_port}\033[0m")
        run_server(
            host=args.api_host,
            port=args.api_port,
            defense_mode=args.mode,
            ai_provider=args.provider,
            db_path=args.db,
        )
        return

    from schild.core.agent import SchildAgent
    defense_mode = DefenseMode(args.mode)

    try:
        provider_enum = AIProvider(args.provider)
    except ValueError:
        print(f"Unknown provider: {args.provider}")
        sys.exit(1)

    agent = SchildAgent(
        defense_mode=defense_mode,
        db_path=args.db,
        ai_provider=provider_enum,
    )

    # One-shot modes
    # DONE: TASK-07
    if args.backup:
        path = agent.memory.backup(backup_dir=args.backup_dir)
        print(f"{COLORS['success']}  Backup saved: {path}{COLORS['reset']}")
        return

    if args.hunt:
        agent.hunt()
        return

    if args.hunt_id:
        agent.hunt(hypothesis_id=args.hunt_id.upper())
        return

    if args.zeroday:
        agent.zero_day_scan()
        return

    if args.anomaly:
        agent.anomaly_scan()
        return

    if args.baseline:
        agent.build_baseline(samples=args.baseline_samples)
        return

    if args.ml_train:
        agent.anomaly_detector.train(n_samples=args.baseline_samples)
        return

    if args.ml_retrain:
        agent.anomaly_detector.retrain(n_samples=args.baseline_samples)
        return

    if args.ml_update:
        agent.anomaly_detector.update_online(n_new=args.baseline_samples // 2)
        return

    if args.enrich:
        agent.enrich_ioc(args.enrich[0], args.enrich[1])
        return
        
    if args.prompt:
        agent.single_prompt(" ".join(args.prompt))
        return

    # DONE: TASK-08 — start ingestion if requested
    if args.syslog:
        agent.start_syslog_ingestion(port=args.syslog_port)

    if args.watch_log:
        for log_path in args.watch_log:
            agent.watch_log_file(log_path)

    # DONE: TASK-09 — start scheduled hunts if requested
    if args.schedule:
        agent.start_scheduled_hunt(interval_minutes=args.schedule)

    # DONE: TASK-11.8
    sidecar_secret = args.sidecar_secret
    if args.sidecar:
        if not sidecar_secret:
            print(f"{COLORS['error']}  Error: --sidecar requires --sidecar-secret "
                  f"or SCHILD_SIDECAR_SECRET env var.{COLORS['reset']}")
            return
        for entry in args.sidecar:
            if "=" not in entry:
                print(f"{COLORS['error']}  Invalid --sidecar format: {entry!r}. "
                      f"Use NAME=URL (e.g. dvwa=http://10.0.0.5:8421){COLORS['reset']}")
                return
            name, url = entry.split("=", 1)
            agent.register_sidecar(name=name.strip(), url=url.strip(), secret=sidecar_secret)

    if args.ping_sidecars:
        results = agent.ping_sidecars()
        if not results:
            print("No sidecars registered.")
        for host, alive in results.items():
            status = f"{COLORS['success']}UP{COLORS['reset']}" if alive else f"{COLORS['error']}DOWN{COLORS['reset']}"
            print(f"  {host}: {status}")
        return

    # Interactive CLI
    agent.run()


if __name__ == "__main__":
    main()
