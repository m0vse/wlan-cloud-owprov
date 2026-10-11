FROM openwifi-access-policy-tests:20261011
COPY src/framework/UserAccessPolicy.h src/framework/UserAccessResolver.h /tests/framework/
COPY tests/access-control/resolver_test.cpp /tests/
RUN g++ -std=c++17 -Wall -Wextra -Werror -I /tests /tests/resolver_test.cpp -o /tests/resolver-test
CMD ["sh", "-c", "./policy-test && ./policy-json-test && ./resolver-test"]
