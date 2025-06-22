#define DUCKDB_EXTENSION_MAIN

#include "pdf_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

// OpenSSL linked through vcpkg
#include <openssl/opensslv.h>

namespace duckdb {

inline void PdfScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &name_vector = args.data[0];
	UnaryExecutor::Execute<string_t, string_t>(name_vector, result, args.size(), [&](string_t name) {
		return StringVector::AddString(result, "Pdf " + name.GetString() + " 🐥");
	});
}

inline void PdfOpenSSLVersionScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &name_vector = args.data[0];
	UnaryExecutor::Execute<string_t, string_t>(name_vector, result, args.size(), [&](string_t name) {
		return StringVector::AddString(result, "Pdf " + name.GetString() + ", my linked OpenSSL version is " +
		                                           OPENSSL_VERSION_TEXT);
	});
}

static void LoadInternal(DatabaseInstance &instance) {
	// Register a scalar function
	auto pdf_scalar_function = ScalarFunction("pdf", {LogicalType::VARCHAR}, LogicalType::VARCHAR, PdfScalarFun);
	ExtensionUtil::RegisterFunction(instance, pdf_scalar_function);

	// Register another scalar function
	auto pdf_openssl_version_scalar_function = ScalarFunction("pdf_openssl_version", {LogicalType::VARCHAR},
	                                                            LogicalType::VARCHAR, PdfOpenSSLVersionScalarFun);
	ExtensionUtil::RegisterFunction(instance, pdf_openssl_version_scalar_function);
}

void PdfExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}
std::string PdfExtension::Name() {
	return "pdf";
}

std::string PdfExtension::Version() const {
#ifdef EXT_VERSION_PDF
	return EXT_VERSION_PDF;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void pdf_init(duckdb::DatabaseInstance &db) {
	duckdb::DuckDB db_wrapper(db);
	db_wrapper.LoadExtension<duckdb::PdfExtension>();
}

DUCKDB_EXTENSION_API const char *pdf_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
