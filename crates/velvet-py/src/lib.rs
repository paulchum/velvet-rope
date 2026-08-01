use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pythonize::{depythonize, pythonize};
use serde::Serialize;
use serde_json::Value;
use velvet_core::{
    CandidateAction, action_registry, evaluate_memory, normalize_action_v1, redact_secrets,
    route_with_policy_graph, route_with_policy_graph_and_thread,
};
#[cfg(feature = "legacy-heuristic-routing")]
use velvet_core::{RouterConfig, score_action_with_pricing};
use velvet_policy_loader::{PolicyLoadError, PolicyRuntime};

fn to_value(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    depythonize(value).map_err(|error| PyValueError::new_err(error.to_string()))
}

fn to_candidates(value: &Bound<'_, PyAny>) -> PyResult<Vec<CandidateAction>> {
    depythonize(value).map_err(|error| PyValueError::new_err(error.to_string()))
}

fn into_python<T: Serialize>(py: Python<'_>, value: &T) -> PyResult<Py<PyAny>> {
    pythonize(py, value)
        .map(Bound::unbind)
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

fn load_error(errors: Vec<PolicyLoadError>) -> PyErr {
    PyValueError::new_err(
        errors
            .into_iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

#[pyclass]
struct NativeRouter {
    runtime: PolicyRuntime,
    chain: String,
}

#[pymethods]
impl NativeRouter {
    #[new]
    #[pyo3(signature = (policy_dir="policies".to_string(), chain="default".to_string(), watch=false))]
    fn new(policy_dir: String, chain: String, watch: bool) -> PyResult<Self> {
        Ok(Self {
            runtime: PolicyRuntime::new(policy_dir, watch).map_err(load_error)?,
            chain,
        })
    }

    fn route_decision(
        &self,
        py: Python<'_>,
        state: &Bound<'_, PyAny>,
        candidates: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let state = to_value(state)?;
        let candidates = to_candidates(candidates)?;
        let graph = self.runtime.snapshot();
        let decision = route_with_policy_graph(&state, &candidates, &graph, &self.chain)
            .map_err(PyValueError::new_err)?;
        into_python(py, &decision)
    }

    #[pyo3(signature = (state, candidates, thread_id=None, timestamp=None))]
    fn route_thread(
        &self,
        py: Python<'_>,
        state: &Bound<'_, PyAny>,
        candidates: &Bound<'_, PyAny>,
        thread_id: Option<String>,
        timestamp: Option<String>,
    ) -> PyResult<Py<PyAny>> {
        let state = to_value(state)?;
        let candidates = to_candidates(candidates)?;
        let graph = self.runtime.snapshot();
        let result = route_with_policy_graph_and_thread(
            &state,
            &candidates,
            &graph,
            &self.chain,
            thread_id,
            timestamp,
        )
        .map_err(PyValueError::new_err)?;
        into_python(py, &result)
    }
}

fn default_router() -> PyResult<NativeRouter> {
    NativeRouter::new("policies".to_string(), "default".to_string(), false)
}

#[pyfunction]
fn route_decision(
    py: Python<'_>,
    state: &Bound<'_, PyAny>,
    candidates: &Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    default_router()?.route_decision(py, state, candidates)
}

#[pyfunction]
#[pyo3(signature = (state, candidates, thread_id=None, timestamp=None))]
fn route_thread(
    py: Python<'_>,
    state: &Bound<'_, PyAny>,
    candidates: &Bound<'_, PyAny>,
    thread_id: Option<String>,
    timestamp: Option<String>,
) -> PyResult<Py<PyAny>> {
    default_router()?.route_thread(py, state, candidates, thread_id, timestamp)
}

#[cfg(feature = "legacy-heuristic-routing")]
#[pyfunction]
fn score_action(
    py: Python<'_>,
    state: &Bound<'_, PyAny>,
    candidate: &Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    let state = to_value(state)?;
    let candidate: CandidateAction =
        depythonize(candidate).map_err(|error| PyValueError::new_err(error.to_string()))?;
    let config = RouterConfig::from_state(&state);
    let score = score_action_with_pricing(&candidate, &state, &config.pricing_context);
    into_python(py, &score)
}

#[pyfunction]
#[pyo3(signature = (content, context, timestamp=None))]
fn memory_decision(
    py: Python<'_>,
    content: &str,
    context: &Bound<'_, PyAny>,
    timestamp: Option<String>,
) -> PyResult<Py<PyAny>> {
    let context = to_value(context)?;
    into_python(py, &evaluate_memory(content, &context, timestamp))
}

#[pyfunction]
fn redact(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    into_python(py, &redact_secrets(to_value(value)?))
}

#[pyfunction]
fn registry(py: Python<'_>) -> PyResult<Py<PyAny>> {
    let definitions = action_registry().into_values().collect::<Vec<_>>();
    into_python(py, &definitions)
}

#[pyfunction]
#[pyo3(signature = (proposal, contract=None))]
fn normalize_action(
    py: Python<'_>,
    proposal: &Bound<'_, PyAny>,
    contract: Option<&Bound<'_, PyAny>>,
) -> PyResult<Py<PyAny>> {
    let proposal = to_value(proposal)?;
    let contract = match contract {
        Some(value) => Some(to_value(value)?),
        None => None,
    };
    let action = normalize_action_v1(&proposal, contract.as_ref())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    into_python(py, &action.to_payload())
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeRouter>()?;
    module.add_function(wrap_pyfunction!(route_decision, module)?)?;
    module.add_function(wrap_pyfunction!(route_thread, module)?)?;
    #[cfg(feature = "legacy-heuristic-routing")]
    module.add_function(wrap_pyfunction!(score_action, module)?)?;
    module.add_function(wrap_pyfunction!(memory_decision, module)?)?;
    module.add_function(wrap_pyfunction!(redact, module)?)?;
    module.add_function(wrap_pyfunction!(registry, module)?)?;
    module.add_function(wrap_pyfunction!(normalize_action, module)?)?;
    Ok(())
}
