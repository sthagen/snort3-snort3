//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// js_pdf_norm.h author Cisco

#ifndef JS_PDF_NORM_H
#define JS_PDF_NORM_H

#include <cstring>

// This follows the prefix from pdf_tokenizer.l
#undef yyFlexLexer
#define yyFlexLexer pdfFlexLexer
#include <FlexLexer.h>

#include "helpers/streambuf.h"
#include "js_norm/js_norm.h"
#include "js_norm/pdf_tokenizer.h"

namespace snort
{

class SO_PUBLIC PDFJSNorm : public JSNorm
{
public:
    static bool is_pdf(const void* data, size_t len)
    {
        constexpr char magic[] = "%PDF-1.";
        constexpr int magic_len = sizeof(magic) - 1;
        return magic_len < len and !strncmp((const char*)data, magic, magic_len);
    }

    PDFJSNorm(JSNormConfig* cfg, uint32_t gen_id) :
        JSNorm(cfg, false, gen_id),
        pdf_in(&buf_pdf_in), pdf_out(&buf_pdf_out),
        extractor(pdf_in, pdf_out, state_buf, state_len, cfg ? cfg->pdf_max_dictionary_depth : 0)
    { }

    virtual ~PDFJSNorm() override
    { delete[] state_buf; }

protected:
    bool pre_proc() override;
    bool post_proc(int) override;

private:
    char* state_buf = nullptr;
    int state_len = 0;
    snort::istreambuf_glue buf_pdf_in;
    snort::ostreambuf_infl buf_pdf_out;
    std::istream pdf_in;
    std::ostream pdf_out;
    jsn::PDFTokenizer extractor;
};

}

#endif
