##! TrafficLens: логи в JSON, хэши всех файлов, извлечение переданных файлов.

@load policy/tuning/json-logs
@load frameworks/files/hash-all-files
@load base/files/extract
@load policy/protocols/ssl/validate-certs
@load policy/protocols/conn/mac-logging

module TrafficLens;

export {
	## Извлекать ли переданные файлы на диск (каталог ./extract_files/).
	const extract_enabled = T &redef;
}

redef FileExtract::prefix = "./extract_files/";

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	if ( ! extract_enabled )
		return;
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
	                    Files::AnalyzerArgs($extract_filename=fmt("%s-%s", f$source, f$id)));
	}
