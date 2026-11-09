#!/bin/sh

set -eux

export TZ='UTC0'

cleanup()
{
	rm -rf "${TMP:-}"
	exit
}

TMP="$(mktemp -d)"
trap cleanup EXIT HUP INT QUIT ABRT ALRM TERM

for rec in test/rec/*.rec; do
	_sample="$(basename "${rec}" ".rec")"
	_output="${TMP}/output/${_sample}"

	./semonitor.py -v -x -r "${_output}.__date__.rec" -o "${_output}.__date__.json" "test/rec/${_sample}.rec"
	mv "${_output}."[0-9]*".json" "${_output}.json"
	mv "${_output}."[0-9]*".rec" "${_output}.rec"
	diff "test/json/${_sample}.json" "${_output}.json"
	cmp "test/rec/${_sample}.rec" "${_output}.rec"

	_tmpse2csv="${_output}.se2csv"
	mkdir "${_tmpse2csv}"
	./conversion/se2csv.py -p "${_tmpse2csv}/${_sample}" -t < "test/json/${_sample}.json"
	diff -w "test/csv/${_sample}/" "${_tmpse2csv}/"

	./semonitor.py -v -x -r "${_output}.rec" -o "${_output}.json" "test/rec/${_sample}.rec"
	diff "test/json/${_sample}.json" "${_output}.1.json"
	cmp "test/rec/${_sample}.rec" "${_output}.1.rec"

	./semonitor.py -a -v -x -r "${_output}.rec" -o "${_output}.json" "test/rec/${_sample}.rec"
	cat "test/json/${_sample}.json" "test/json/${_sample}.json" | \
	cmp - "${_output}.json"
	cat "test/rec/${_sample}.rec" "test/rec/${_sample}.rec" | \
	cmp - "${_output}.rec"
	test ! -e "${_output}.2.json"
	test ! -e "${_output}.2.rec"
done

# nadir (-n): TZ is UTC0, so the epoch of HH:MM is HH*3600+MM*60 modulo a day
_rec='test/rec/7f104920.rec'
for _nadir in 'default:6000' '04:05:14700' '0:00:0' '23:59:86340'; do
	_epoch="$(./semonitor.py -v -n "${_nadir%:*}" "${_rec}" 2>&1 > '/dev/null' | \
	          sed -n 's/^nadir at epoch \([0-9]*\) .*/\1/p')"
	test "$((_epoch % 86400))" -eq "${_nadir##*:}"
done

# nadir needs a valid 24h HH:MM (or 'default') and is rejected otherwise
for _nadir in '25:00' '1:60' '1:40am' 'reset'; do
	_rc='0'
	./semonitor.py -n "${_nadir}" "${_rec}" > '/dev/null' 2>&1 || _rc="${?}"
	test "${_rc}" -eq 2
done
_rc='0'
./semonitor.py -n > '/dev/null' 2>&1 || _rc="${?}"
test "${_rc}" -eq 2
