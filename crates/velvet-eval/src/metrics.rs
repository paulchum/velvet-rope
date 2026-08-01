#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConfidenceInterval {
    pub estimate: f64,
    pub lower: f64,
    pub upper: f64,
}

pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

pub fn brier_score(confidence_outcomes: &[(f64, bool)]) -> f64 {
    if confidence_outcomes.is_empty() {
        return 0.0;
    }
    mean(
        &confidence_outcomes
            .iter()
            .map(|(confidence, outcome)| {
                let actual = if *outcome { 1.0 } else { 0.0 };
                (confidence - actual).powi(2)
            })
            .collect::<Vec<_>>(),
    )
}

pub fn expected_calibration_error(confidence_outcomes: &[(f64, bool)], bins: usize) -> f64 {
    if confidence_outcomes.is_empty() || bins == 0 {
        return 0.0;
    }
    let mut total = 0.0;
    for bin in 0..bins {
        let lower = bin as f64 / bins as f64;
        let upper = (bin + 1) as f64 / bins as f64;
        let items = confidence_outcomes
            .iter()
            .filter(|(confidence, _)| {
                if bin + 1 == bins {
                    *confidence >= lower && *confidence <= upper
                } else {
                    *confidence >= lower && *confidence < upper
                }
            })
            .collect::<Vec<_>>();
        if items.is_empty() {
            continue;
        }
        let avg_confidence =
            items.iter().map(|(confidence, _)| *confidence).sum::<f64>() / items.len() as f64;
        let accuracy =
            items.iter().filter(|(_, outcome)| *outcome).count() as f64 / items.len() as f64;
        total += (items.len() as f64 / confidence_outcomes.len() as f64)
            * (avg_confidence - accuracy).abs();
    }
    total
}

pub fn bca_mean_ci(values: &[f64], resamples: usize, seed: u64) -> ConfidenceInterval {
    if values.is_empty() {
        return ConfidenceInterval {
            estimate: 0.0,
            lower: 0.0,
            upper: 0.0,
        };
    }
    if values.len() == 1 || resamples == 0 {
        let estimate = values[0];
        return ConfidenceInterval {
            estimate,
            lower: estimate,
            upper: estimate,
        };
    }
    let estimate = mean(values);
    let mut rng = Lcg::new(seed);
    let mut boot = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        let mut sum = 0.0;
        for _ in values {
            sum += values[rng.next_usize(values.len())];
        }
        boot.push(sum / values.len() as f64);
    }
    boot.sort_by(f64::total_cmp);

    let below = boot.iter().filter(|value| **value < estimate).count() as f64;
    let z0 = inverse_normal_cdf(clamp_probability(below / boot.len() as f64));
    let jack = jackknife_means(values);
    let jack_mean = mean(&jack);
    let numerator = jack
        .iter()
        .map(|value| (jack_mean - value).powi(3))
        .sum::<f64>();
    let denominator = 6.0
        * jack
            .iter()
            .map(|value| (jack_mean - value).powi(2))
            .sum::<f64>()
            .powf(1.5);
    let acceleration = if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    };
    let lower_alpha = adjusted_alpha(0.025, z0, acceleration);
    let upper_alpha = adjusted_alpha(0.975, z0, acceleration);
    ConfidenceInterval {
        estimate,
        lower: quantile(&boot, lower_alpha),
        upper: quantile(&boot, upper_alpha),
    }
}

fn jackknife_means(values: &[f64]) -> Vec<f64> {
    let total = values.iter().sum::<f64>();
    values
        .iter()
        .map(|value| (total - value) / (values.len() - 1) as f64)
        .collect()
}

fn adjusted_alpha(alpha: f64, z0: f64, acceleration: f64) -> f64 {
    let z_alpha = inverse_normal_cdf(alpha);
    normal_cdf(z0 + (z0 + z_alpha) / (1.0 - acceleration * (z0 + z_alpha)))
}

fn quantile(sorted: &[f64], probability: f64) -> f64 {
    let probability = clamp_probability(probability);
    let index = ((sorted.len() - 1) as f64 * probability).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn clamp_probability(value: f64) -> f64 {
    value.clamp(1e-12, 1.0 - 1e-12)
}

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9e3779b97f4a7c15,
        }
    }

    fn next_usize(&mut self, upper: usize) -> usize {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.state >> 32) as usize) % upper
    }
}

fn normal_cdf(x: f64) -> f64 {
    0.5 * (1.0 + erf(x / 2.0_f64.sqrt()))
}

fn erf(x: f64) -> f64 {
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let y = 1.0
        - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
            + 0.254829592)
            * t
            * (-x * x).exp();
    sign * y
}

#[allow(clippy::excessive_precision)]
fn inverse_normal_cdf(p: f64) -> f64 {
    let p = clamp_probability(p);
    let a = [
        -3.969683028665376e+01,
        2.209460984245205e+02,
        -2.759285104469687e+02,
        1.383577518672690e+02,
        -3.066479806614716e+01,
        2.506628277459239e+00,
    ];
    let b = [
        -5.447609879822406e+01,
        1.615858368580409e+02,
        -1.556989798598866e+02,
        6.680131188771972e+01,
        -1.328068155288572e+01,
    ];
    let c = [
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e+00,
        -2.549732539343734e+00,
        4.374664141464968e+00,
        2.938163982698783e+00,
    ];
    let d = [
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e+00,
        3.754408661907416e+00,
    ];
    let plow = 0.02425;
    let phigh = 1.0 - plow;
    if p < plow {
        let q = (-2.0 * p.ln()).sqrt();
        (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5])
            / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    } else if p <= phigh {
        let q = p - 0.5;
        let r = q * q;
        (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q
            / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5])
            / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest::proptest! {
        #[test]
        fn brier_score_stays_in_unit_interval(values in proptest::collection::vec((0.0f64..1.0, proptest::bool::ANY), 1..100)) {
            let score = brier_score(&values);
            proptest::prop_assert!((0.0..=1.0).contains(&score));
        }

        #[test]
        fn ece_stays_in_unit_interval(values in proptest::collection::vec((0.0f64..1.0, proptest::bool::ANY), 1..100)) {
            let score = expected_calibration_error(&values, 10);
            proptest::prop_assert!((0.0..=1.0).contains(&score));
        }
    }

    #[test]
    fn bootstrap_is_seed_deterministic() {
        let values = [1.0, 0.0, 1.0, 1.0, 0.0];
        assert_eq!(
            bca_mean_ci(&values, 1000, 42),
            bca_mean_ci(&values, 1000, 42)
        );
    }
}
