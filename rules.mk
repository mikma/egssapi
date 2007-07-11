SUBST = sed $(ERLANG_LIB_VER_SUBST) \
	-e 's/[@]$(OPT_APP)_VSN[@]/$($(OPT_APP)_VSN)/'

%.rel: %.rel.in
	$(SUBST) $< > $@

%.beam: %.erl
	@echo [ERLC] $@
	@$(ERLC) $(AM_ERL_FLAGS) $(ERL_FLAGS) $(AM_ERLCFLAGS) $(ERLCFLAGS) $<

%.app: %.app-in
	$(SUBST) $< > $@

%.boot: %.rel %.app
	@echo [ERLC] $@
	@$(ERLC) $(AM_ERL_FLAGS) $(ERL_FLAGS) $(AM_ERLCFLAGS) $(ERLCFLAGS) $<
