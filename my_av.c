// Copyright Marina Oprea 313CAb 2022-2023

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define URL_SIZE 1000
#define DOMAIN_SIZE 1000
#define TRAFFIC_LINE 1000

// function loads malicious domains database
char **load_database(int *dim)
{
	FILE *in = fopen("data/urls/domains_database", "r");
	char **domains = NULL;
	char *s = malloc(DOMAIN_SIZE * sizeof(char));
	while (fgets(s, DOMAIN_SIZE, in)) {
		s[strlen(s) - 1] = '\0';
		(*dim)++;
		if (domains)
			domains = realloc(domains, (*dim) * sizeof(char *));
		else
			domains = malloc((*dim) * sizeof(char *));
		domains[(*dim) - 1] = malloc((strlen(s) + 1) * sizeof(char));
		strcpy(domains[(*dim) - 1], s);
	}

	free(s);
	fclose(in);
	return domains;
}

// function searches given database for malicious domains
// linear implementation
int search_database(char **database, int dim, char *s)
{
	for (int i = 0; i < dim; i++)
		if (!strcmp(database[i], s))
			return 1;
	return 0;
}

// function checks for accessing executable file
int is_executable(char *s)
{
	char *p = strrchr(s, '.');
	if (p && !strcmp(p, ".exe"))
		return 1;
	return 0;
}

// function checks for number of digits in domain name
int check_digits(char *s)
{
	int nr = 0;
	int n = strlen(s);
	for (int i = 0; i < n; i++)
		if (s[i] >= '0' && s[i] <= '9')
			nr++;
	if (nr * 10 >= n) // avoid losing precision by working on float
		return 1;
	return 0;
}

// function checks for "www-" or other variants
int check_www(char *domain)
{
	char *p = strstr(domain, "www");
	if (p && *(p + 1) != '.')
		return 1;
	return 0;
}

// function checks for malicious tlds
int check_tld(char *domain)
{
	char *p = strrchr(domain, '.');
	if (p && !strcmp(p, ".ru"))
		return 1;
	if (p && !strcmp(p, ".casa"))
		return 1;
	if (p && !strcmp(p, ".cc"))
		return 1;
	if (p && !strcmp(p, ".jp"))
		return 1;
	return 0;
}

// function checks for underscores in domain name and more than 2 tlds
int check(char *domain)
{
	if (strchr(domain, '_'))
		return 1;
	int nr = 0;
	int n = strlen(domain);
	for (int i = 0; i < n; i++)
		if (domain[i] == '.')
			nr++;
	if (nr > 2)
		return 1;
	return 0;
}

void exit_task1(char **database, int dim, char *domain, char *url)
{
	free(domain);
	free(url);
	for (int i = 0; i < dim; i++)
		free(database[i]);
	free(database);
}

// solves task1
void task1(void)
{
	int dim = 0;
	char **database = NULL;
	database = load_database(&dim);

	// make sure space for final '\0' is allocated
	char *url = malloc((URL_SIZE + 1) * sizeof(char));
	char *domain = malloc((DOMAIN_SIZE + 1) * sizeof(char));

	FILE *in = fopen("data/urls/urls.in", "r");
	FILE *out = fopen("urls-predictions.out", "w");

	while (fgets(url, URL_SIZE, in)) {
		url[strlen(url) - 1] = '\0';
		if (!strchr(url, '/')) {
			int ans = 0;
			ans |= search_database(database, dim, url);
			ans |= is_executable(url);
			ans |= check_digits(url);
			fprintf(out, "%d\n", ans);
			continue;
		}
		int nr = strchr(url, '/') - url; // position of '/'
		strncpy(domain, url, nr);
		domain[nr] = '\0';
		int ans = 0; // benign
		// every check function returns 1 for malicious prediction, 0 otherwise
		ans |= search_database(database, dim, domain);
		ans |= is_executable(url);
		ans |= check_digits(domain);
		ans |= check_www(domain);
		ans |= check_tld(domain);
		ans |= check(domain);
		fprintf(out, "%d\n", ans);
	}

	exit_task1(database, dim, domain, url); // free used resources
	fclose(in);
	fclose(out);
}

void task2(void)
{
	FILE *in2 = fopen("data/traffic/traffic.in", "r");
	FILE *out2 = fopen("traffic-predictions.out", "w");

	char *line = malloc((TRAFFIC_LINE + 1) * sizeof(char));
	fgets(line, TRAFFIC_LINE, in2);
	line[strlen(line) - 1] = '\0';
	char *p = strtok(line, ",");
	int index = 1;
	int index1, index2;
	while (p) {
		if (!strcmp(p, "flow_duration"))
			index1 = index;
		if (!strcmp(p, "flow_pkts_payload.avg"))
			index2 = index;
		index++;
		p = strtok(NULL, ",");
	}

	while (fgets(line, TRAFFIC_LINE, in2)) {
		line[strlen(line) - 1] = '\0';
		p = strtok(line, ",");
		index = 1;
		int ans = 0; // benign
		while (p) {
			if (index == index1) {
				char c1, c2, c3, c4, c5, c6;
				int aux;
				char aux2[7], aux3[12]; // parse known format
				int rc = sscanf(p, "%d %s %c%c:%c%c:%c%c.%s", &aux, aux2, &c1,
				&c2, &c3, &c4, &c5, &c6, aux3);
				if (aux || c1 != '0' || c2 != '0' || c3 != '0' || c4 != '0' ||
					c5 != '0' || c6 > '1')
					ans = 1;
				else // use atoll for better precision, loading more decimals
					if (c6 == '1' && atoll(aux3) != 0LL)
						ans = 1;
			} else {
				if (index == index2)
					if (ans == 1 && atof(p) == 0.)
						ans = 0;
					else
						;
			}
			index++;
			p = strtok(NULL, ",");
		}
		fprintf(out2, "%d\n", ans);
	}

	free(line);
	fclose(in2);
	fclose(out2);
}

// main function calls for the tasks' implementation
int main(void)
{
	task1();
	task2();

	return 0;
}
