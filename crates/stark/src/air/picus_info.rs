use std::collections::HashMap;
/// Information about Picus annotations on AIR columns.
#[derive(Debug, Clone, Default)]
pub struct PicusInfo {
    /// Column to name mapping. column i will get map to the string "f_i" where f is the field
    /// in the column struct that contains column i
    pub col_to_name: HashMap<usize, String>,
    /// Ranges of columns marked as inputs.
    /// Each tuple contains (`start_index`, `end_index`, `field_name`) where:
    /// - `start_index` is the first column index (inclusive)
    /// - `end_index` is the last column index (exclusive)
    /// - `field_name` is the name of the field
    pub input_ranges: Vec<(usize, usize, String)>,

    /// Ranges of columns marked as outputs.
    /// Each tuple contains (`start_index`, `end_index`, `field_name`) where:
    /// - `start_index` is the first column index (inclusive)
    /// - `end_index` is the last column index (exclusive)
    /// - `field_name` is the name of the field
    pub output_ranges: Vec<(usize, usize, String)>,

    /// Indices of columns marked as selectors.
    /// Each tuple contains (`column_index`, `field_name`) where:
    /// - `column_index` is the index of the selector column
    /// - `field_name` is the name of the field
    pub selector_indices: Vec<(usize, String)>,
}
