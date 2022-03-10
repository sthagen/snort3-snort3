//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// js_identifier_ctx.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef JS_IDENTIFIER_CTX
#define JS_IDENTIFIER_CTX

#include <list>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

enum JSProgramScopeType : unsigned int
{
    GLOBAL = 0,     // the global scope (the initial one)
    FUNCTION,       // function declaration
    BLOCK,          // block of code and object declaration
    PROG_SCOPE_TYPE_MAX
};

class JSIdentifierCtxBase
{
public:
    virtual ~JSIdentifierCtxBase() = default;

    virtual const char* substitute(const char* identifier) = 0;
    virtual void add_alias(const char* alias, const std::string&& value) = 0;
    virtual const char* alias_lookup(const char* alias) const = 0;
    virtual bool is_ignored(const char* identifier) const = 0;

    virtual bool scope_push(JSProgramScopeType) = 0;
    virtual bool scope_pop(JSProgramScopeType) = 0;

    virtual void reset() = 0;

    virtual size_t size() const = 0;
};

class JSIdentifierCtx : public JSIdentifierCtxBase
{
public:
    JSIdentifierCtx(int32_t depth, uint32_t max_scope_depth,
        const std::unordered_set<std::string>& ignore_list);

    virtual const char* substitute(const char* identifier) override;
    virtual void add_alias(const char* alias, const std::string&& value) override;
    virtual const char* alias_lookup(const char* alias) const override;
    virtual bool is_ignored(const char* identifier) const override;

    virtual bool scope_push(JSProgramScopeType) override;
    virtual bool scope_pop(JSProgramScopeType) override;

    virtual void reset() override;

    // approximated to 500 unique mappings insertions
    // approximated to 3 program scopes in the list
    virtual size_t size() const override
    { return (sizeof(JSIdentifierCtx) + (sizeof(std::string) * 2 * 500) +
        (sizeof(ProgramScope) * 3)); }

private:
    using Alias = std::vector<std::string>;
    using AliasRef = std::list<Alias*>;
    using AliasMap = std::unordered_map<std::string, Alias>;
    using NameMap = std::unordered_map<std::string, const char*>;

    class ProgramScope
    {
    public:
        ProgramScope(JSProgramScopeType t) : t(t)
        {}

        ~ProgramScope()
        { for (auto a : to_remove) a->pop_back(); }

        void reference(Alias& a)
        { to_remove.push_back(&a); }

        JSProgramScopeType type() const
        { return t; }

    private:
        JSProgramScopeType t;
        AliasRef to_remove{};
    };

    inline const char* substitute(unsigned char c);

    // do not swap next two lines, the destructor frees them in the reverse order
    AliasMap aliases;
    std::list<ProgramScope> scopes;

    const char* id_fast[256];
    NameMap id_names;
    const std::unordered_set<std::string>& ignore_list;

    const char* norm_name;
    const char* norm_name_end;
    uint32_t max_scope_depth;

// advanced program scope access for testing
#if defined(CATCH_TEST_BUILD) || defined(BENCHMARK_TEST)
public:
    // compare scope list with the passed pattern
    bool scope_check(const std::list<JSProgramScopeType>& compare) const;
    const std::list<JSProgramScopeType> get_types() const;
#endif // CATCH_TEST_BUILD
};

#endif // JS_IDENTIFIER_CTX
