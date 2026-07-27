from datetime import datetime

from pipeline import (
    log,
    load_model_artefacts,
    discover_devices,
    collect_traffic,
    prepare_features,
    generate_fingerprints,
    summarize_by_device,
    plot_device_fingerprints, 
    CSV_PATH,
    OUTPUT_PATH,
)

import pandas as pd

def main():
    log("=" * 60)
    log("  Fingerprint Pipeline Starting")
    log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 60)

    # 1. Load model artefacts
    model, le, feature_columns = load_model_artefacts()

    # 2. Discover devices from first flush
    devices, _, file_state = discover_devices(CSV_PATH)
    n_devices = len(devices)

    # 3. Collect traffic across optimal number of flushes
    df_collected = collect_traffic(CSV_PATH, file_state, n_devices)

    # 4. Prepare features
    X, df_meta = prepare_features(df_collected, feature_columns)
    log(f"Feature matrix ready — {X.shape[0]:,} rows × {X.shape[1]} features")

    X, df_meta = prepare_features(df_collected, feature_columns)

    # Diagnostic — check how many features are actually populated
    zero_cols    = (X == 0).all()
    missing_cols = zero_cols[zero_cols].index.tolist()
    present_cols = zero_cols[~zero_cols].index.tolist()

    log(f"Features with real values: {len(present_cols)} — {present_cols}")
    log(f"Features zeroed out:       {len(missing_cols)} — {missing_cols}")

    # 5. Generate fingerprints
    log("Generating fingerprints...")
    fingerprint_df = generate_fingerprints(model, X, le)
    log(f"Fingerprints generated — "
        f"{fingerprint_df['fingerprint_hash'].nunique():,} unique hashes")

    # 6. Per-device summary
    combined_df, summary_df = summarize_by_device(df_meta, fingerprint_df)

    # 7. Plot device fingerprints
    log("Generating device fingerprint plots...")
    plot_device_fingerprints(
        model          = model,
        X              = X,
        df_meta        = combined_df[[c for c in combined_df.columns
                                    if c in ['src_ip', 'window_start',
                                            'container_name']]],
        fingerprint_df = fingerprint_df,
        top_n_features = 15,
        output_path    = "device_fingerprints.png"
    )

    # 8. Save results
    combined_df.to_csv(OUTPUT_PATH, index=False)
    log(f"Full results saved to {OUTPUT_PATH}")

    summary_df.to_csv("device_summary.csv", index=False)
    log("Device summary saved to device_summary.csv")

    # 9. Final attack alert
    attacked = summary_df[summary_df['attack_rows'] > 0]['device'].tolist()
    if attacked:
        log(f"ATTACKS DETECTED on: {attacked}")
    else:
        log("No attacks detected across all devices.")

    log("Pipeline complete.")
    return combined_df, summary_df, "device_fingerprints.png"

if __name__ == "__main__":
    main()