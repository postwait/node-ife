/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>

#include <sys/types.h>
#include <sys/mman.h>

#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef __APPLE__
#include <stdlib.h>
#include <malloc.h>
#endif

namespace node {

  using namespace v8;

  class IFE : ObjectWrap {

  public:
    static void Initialize(v8::Handle<v8::Object> target);

    static v8::Handle<v8::Value> New(const v8::Arguments& args);
    static v8::Handle<v8::Value> list(const v8::Arguments& args);
    static v8::Handle<v8::Value> up(const v8::Arguments& args);
    static v8::Handle<v8::Value> down(const v8::Arguments& args);
    static v8::Handle<v8::Value> gratarp(const v8::Arguments& args);
    static v8::Handle<v8::Value> arpcache(const v8::Arguments& args);

    IFE();
    ~IFE();
    void emit(Local<Value> args[], int nargs);
  private:
    static Persistent<FunctionTemplate> constructor_template;
  };

  void InitIFE(v8::Handle<v8::Object> target);
}
