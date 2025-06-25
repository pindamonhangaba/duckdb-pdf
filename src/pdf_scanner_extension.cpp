#define DUCKDB_EXTENSION_MAIN

#include "pdf_scanner_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/function/replacement_scan.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"


#include <fstream>
#include <sstream>
#include "mupdf/fitz.h"

namespace duckdb {

struct PdfExtractRow {
    std::string text;
    double x;
    double y;
    double width;
    double height;
    double rotation;
};

struct PdfExtractData : public duckdb::GlobalTableFunctionState {
    std::vector<PdfExtractRow> rows;
    idx_t row_idx = 0;
};

struct PdfExtractBindData : public duckdb::FunctionData {
    std::string file;
    std::string mode;
    PdfExtractBindData(std::string file, std::string mode) : file(std::move(file)), mode(std::move(mode)) {}
    unique_ptr<FunctionData> Copy() const override {
        return make_uniq<PdfExtractBindData>(file, mode);
    }
    bool Equals(const FunctionData &other_p) const override {
        auto &other = (const PdfExtractBindData &)other_p;
        return file == other.file && mode == other.mode;
    }
};

static void AppendUTF8(std::string &out, int codepoint) {
    if (codepoint < 0x80) {
        out += (char)codepoint;
    } else if (codepoint < 0x800) {
        out += (char)(0xC0 | (codepoint >> 6));
        out += (char)(0x80 | (codepoint & 0x3F));
    } else if (codepoint < 0x10000) {
        out += (char)(0xE0 | (codepoint >> 12));
        out += (char)(0x80 | ((codepoint >> 6) & 0x3F));
        out += (char)(0x80 | (codepoint & 0x3F));
    } else {
        out += (char)(0xF0 | (codepoint >> 18));
        out += (char)(0x80 | ((codepoint >> 12) & 0x3F));
        out += (char)(0x80 | ((codepoint >> 6) & 0x3F));
        out += (char)(0x80 | (codepoint & 0x3F));
    }
}

static std::vector<PdfExtractRow> ExtractPdfRows(const std::string &filepath, const std::string &mode) {
    std::vector<PdfExtractRow> rows;
    fz_context *ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
    if (!ctx) {
        throw duckdb::IOException("Cannot create mupdf context");
    }
    try {
        fz_register_document_handlers(ctx);
        fz_document *doc = fz_open_document(ctx, filepath.c_str());
        int page_count = fz_count_pages(ctx, doc);

        for (int i = 0; i < page_count; ++i) {
            fz_page *page = fz_load_page(ctx, doc, i);
            fz_stext_page *stext_page = nullptr;
            try {
                stext_page = fz_new_stext_page_from_page(ctx, page, NULL);
                if (mode == "lines") {
                    for (fz_stext_block *block = stext_page->first_block; block; block = block->next) {
                        if (block->type != FZ_STEXT_BLOCK_TEXT) continue;
                        for (fz_stext_line *line = block->u.t.first_line; line; line = line->next) {
                            std::string line_text;
                            for (fz_stext_char *ch = line->first_char; ch; ch = ch->next) {
                                if (ch->c < 32) continue;
                                AppendUTF8(line_text, ch->c);
                            }
                            if (!line_text.empty()) {
                                rows.push_back(PdfExtractRow{
                                    line_text,
                                    line->bbox.x0,
                                    line->bbox.y0,
                                    line->bbox.x1 - line->bbox.x0,
                                    line->bbox.y1 - line->bbox.y0,
                                    0.0
                                });
                            }
                        }
                    }
                } else if (mode == "chars") {
                    for (fz_stext_block *block = stext_page->first_block; block; block = block->next) {
                        if (block->type != FZ_STEXT_BLOCK_TEXT) continue;
                        for (fz_stext_line *line = block->u.t.first_line; line; line = line->next) {
                            float angle_rad = atan2(line->dir.y, line->dir.x);
                            float angle_deg = angle_rad * (180.0f / M_PI);
                            for (fz_stext_char *ch = line->first_char; ch; ch = ch->next) {
                                if (ch->c < 32) continue;
                                std::string char_text;
                                AppendUTF8(char_text, ch->c);
                                rows.push_back(PdfExtractRow{
                                    char_text,
                                    line->bbox.x0,
                                    line->bbox.y0,
                                    line->bbox.x1 - line->bbox.x0,
                                    line->bbox.y1 - line->bbox.y0,
                                    angle_deg
                                });
                            }
                        }
                    }
                } else if (mode == "full") {
                    std::string page_text;
                    for (fz_stext_block *block = stext_page->first_block; block; block = block->next) {
                        if (block->type != FZ_STEXT_BLOCK_TEXT) continue;
                        for (fz_stext_line *line = block->u.t.first_line; line; line = line->next) {
                            for (fz_stext_char *ch = line->first_char; ch; ch = ch->next) {
                                AppendUTF8(page_text, ch->c);
                            }
                            page_text += '\n';
                        }
                        page_text += '\n';
                    }
                    if (!page_text.empty()) {
                        rows.push_back(PdfExtractRow{
                            page_text, 0, 0, 0, 0, 0
                        });
                    }
                } else {
                    throw duckdb::InvalidInputException("Unknown mode: " + mode);
                }
            } catch (...) {
                if (stext_page) fz_drop_stext_page(ctx, stext_page);
                fz_drop_page(ctx, page);
                throw;
            }
            if (stext_page) fz_drop_stext_page(ctx, stext_page);
            fz_drop_page(ctx, page);
        }
        fz_drop_document(ctx, doc);
    } catch (...) {
        fz_drop_context(ctx);
        throw;
    }
    fz_drop_context(ctx);
    return rows;
}

static unique_ptr<FunctionData> PdfExtractBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &return_types, vector<string> &names) {
    return_types = {LogicalType::VARCHAR, LogicalType::DOUBLE, LogicalType::DOUBLE, LogicalType::DOUBLE, LogicalType::DOUBLE, LogicalType::DOUBLE};
    names = {"text", "x", "y", "width", "height", "rotation"};
    auto file = input.inputs[0].ToString();
    auto mode = input.inputs[1].ToString();
    return make_uniq<PdfExtractBindData>(file, mode);
}

static unique_ptr<GlobalTableFunctionState> PdfExtractInit(ClientContext &context, TableFunctionInitInput &input) {
    auto result = make_uniq<PdfExtractData>();
    auto &bind_data = input.bind_data->Cast<PdfExtractBindData>();
    result->rows = ExtractPdfRows(bind_data.file, bind_data.mode);
    result->row_idx = 0;
    return std::move(result);
}

static void PdfExtractFunc(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
    auto &state = (PdfExtractData &)*input.global_state;
    idx_t count = 0;
    idx_t out_count = MinValue<idx_t>(STANDARD_VECTOR_SIZE, state.rows.size() - state.row_idx);
    for (; count < out_count; count++, state.row_idx++) {
        const auto &row = state.rows[state.row_idx];
        output.SetValue(0, count, Value(row.text));
        output.SetValue(1, count, Value::DOUBLE(row.x));
        output.SetValue(2, count, Value::DOUBLE(row.y));
        output.SetValue(3, count, Value::DOUBLE(row.width));
        output.SetValue(4, count, Value::DOUBLE(row.height));
        output.SetValue(5, count, Value::DOUBLE(row.rotation));
    }
    output.SetCardinality(out_count);
}

// Helper: Encode Unicode codepoint as UTF-8 and append to stringstream
static void AppendUTF8(std::stringstream &ss, int codepoint) {
    if (codepoint < 0x80) {
        ss << (char)codepoint;
    } else if (codepoint < 0x800) {
        ss << (char)(0xC0 | (codepoint >> 6));
        ss << (char)(0x80 | (codepoint & 0x3F));
    } else if (codepoint < 0x10000) {
        ss << (char)(0xE0 | (codepoint >> 12));
        ss << (char)(0x80 | ((codepoint >> 6) & 0x3F));
        ss << (char)(0x80 | (codepoint & 0x3F));
    } else {
        ss << (char)(0xF0 | (codepoint >> 18));
        ss << (char)(0x80 | ((codepoint >> 12) & 0x3F));
        ss << (char)(0x80 | ((codepoint >> 6) & 0x3F));
        ss << (char)(0x80 | (codepoint & 0x3F));
    }
}

static unique_ptr<TableRef> PdfReplacementScan(ClientContext &context, ReplacementScanInput &input,
                                                optional_ptr<ReplacementScanData> data) {
	const auto table_name = ReplacementScan::GetFullPath(input);
	const auto lower_name = StringUtil::Lower(table_name);

	if (!StringUtil::EndsWith(lower_name, ".pdf")) {
		return nullptr;
	}

	auto result = make_uniq<TableFunctionRef>();
	vector<unique_ptr<ParsedExpression>> children;
	children.push_back(make_uniq<ConstantExpression>(Value(table_name)));
	children.push_back(make_uniq<ConstantExpression>(Value("lines")));
	result->function = make_uniq_base<ParsedExpression, FunctionExpression>("pdf_extract", std::move(children));

	return std::move(result);
}

// Register the table function and replacement scan
static void LoadInternal(DatabaseInstance &instance) {
    // Register the table function
    TableFunction pdf_extract_table_func("pdf_extract",
        {LogicalType::VARCHAR, LogicalType::VARCHAR},
        PdfExtractFunc,
        PdfExtractBind,
        PdfExtractInit
    );
    ExtensionUtil::RegisterFunction(instance, pdf_extract_table_func);

    // Register the replacement scan for .pdf files
	instance.config.replacement_scans.emplace_back(PdfReplacementScan);
}

void PdfScannerExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}
std::string PdfScannerExtension::Name() {
	return "pdf_scanner";
}

std::string PdfScannerExtension::Version() const {
#ifdef EXT_VERSION_PDF
	return EXT_VERSION_PDF;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void pdf_scanner_init(duckdb::DatabaseInstance &db) {
	duckdb::DuckDB db_wrapper(db);
	db_wrapper.LoadExtension<duckdb::PdfScannerExtension>();
}

DUCKDB_EXTENSION_API const char *pdf_scanner_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
