extern "C"
{
#include "skel.h"
}
#include <queue>
#include <algorithm>
#include <iostream>
#include <fstream>
using namespace std;
/* Structuri utile in ceea ce urmeaza */
/* Structura care modeleaza tabela de dirijare */
typedef struct route_table
{
  int length;
  struct route_table_entry *entry;
} route_table;

/* Structura care modeleaza tabela ARP*/
typedef struct arp_table
{
  int length;
  struct arp_entry *entry;
} arp_table;

/* Functie care construieste si trimite un pachet ICMP */
void send_icmp_p (uint32_t d_ddr, uint32_t s_ddr, uint8_t * sha, uint8_t * dha,
	     u_int8_t type, u_int8_t code, int interface, int seq, int id)
{

  /* Se formeaza noile antete */
  struct ether_header new_eth_header;
  struct iphdr new_ip_header;
  struct icmphdr icmp_new_header;
  icmp_new_header.type = type;
  icmp_new_header.code = code;
  icmp_new_header.checksum = 0;
  icmp_new_header.un.echo.id = id;
  icmp_new_header.un.echo.sequence = seq;
  packet packet;
  /* Se construieste noul antet eth */
  memcpy ((&new_eth_header)->ether_shost, sha, ETH_ALEN);
  (&new_eth_header)->ether_type = htons (ETHERTYPE_IP);
  memcpy ((&new_eth_header)->ether_dhost, dha, ETH_ALEN);
  /* IPv4 */
  new_ip_header.version = 4;
  new_ip_header.protocol = IPPROTO_ICMP;
  new_ip_header.tot_len =
    htons (sizeof (struct iphdr) + sizeof (struct icmphdr));
  new_ip_header.id = htons (1);
  new_ip_header.frag_off = 0;
  new_ip_header.ihl = 5;
  new_ip_header.tos = 0;
  new_ip_header.check = 0;
  new_ip_header.saddr = s_ddr;
  new_ip_header.daddr = d_ddr;
  new_ip_header.ttl = 64;
  /* Se calculeaza suma de control corespunzatoare */
  new_ip_header.check = ip_checksum (&new_ip_header, sizeof (struct iphdr));
  icmp_new_header.checksum =
    icmp_checksum ((uint16_t *) & icmp_new_header, sizeof (struct icmphdr));
  /* Se formeaza noul pachet cu ajutorul antetelor construite */
  memcpy (packet.payload, &new_eth_header, sizeof (struct ether_header));
  memcpy (packet.payload + sizeof (struct ether_header), &new_ip_header,
	  sizeof (struct iphdr));
  memcpy (packet.payload + sizeof (struct ether_header) +
	  sizeof (struct iphdr), &icmp_new_header, sizeof (struct icmphdr));
  packet.len =
    sizeof (struct ether_header) + sizeof (struct iphdr) +
    sizeof (struct icmphdr);
  packet.interface = interface;
  send_packet (&packet);
}

/* Functie care returneaza antetul ARP din payload */
struct arp_header * get_arp_header (char *input)
{
  struct ether_header *new_eth_header = (struct ether_header *) input;
  if (ntohs (new_eth_header->ether_type) == ETHERTYPE_ARP)
    {
      struct arp_header *arp_hdr =
	(struct arp_header *) (input + sizeof (struct ether_header));
      return arp_hdr;
    }
  else
    return NULL;

}

/* Functie care returneaza o intrare din tabela ARP */
struct arp_entry * get_arp_entry (uint32_t ip, arp_table * arp_table)
{
  for (int i = 0; i < arp_table->length; i++)
    {
      if (ip == arp_table->entry[i].ip)
	return &arp_table->entry[i];
    }
  return NULL;
}

/* Functie care adauga in tabela ARP */
void add_entry_arp (arp_table * arp_table, struct arp_entry elem)
{
  arp_table->entry[arp_table->length] = elem;
  arp_table->length++;
}

/* Functie care returneaza antetul ICMP din payload */
struct icmphdr * get_icmp_header (char *input)
{
  struct ether_header *eth_header = (struct ether_header *) input;
  if (ntohs (eth_header->ether_type) == ETHERTYPE_IP)
    {
      if (((struct iphdr *) (input +
			     sizeof (struct ether_header)))->protocol == 1)
	{
	  struct icmphdr *icmp_header =
	    (struct icmphdr *) (input + sizeof (struct iphdr) +
				sizeof (struct ether_header));
	  return icmp_header;
	}
      else
	return NULL;


    }
  else
    return NULL;
}

/* Functie care construieste si trimite un pachet ARP */
void send_arp_p (uint32_t d_ddr, uint32_t s_ddr,
	    struct ether_header *new_eth_header, int interface,
	    uint16_t arp_op)
{
  struct arp_header arp_hdr;
  packet packet;
  memset (packet.payload, 0, 1000);
  /* Se completeaza informatiile antetului in mod corect */
  arp_hdr.htype = htons (1);
  arp_hdr.ptype = htons (2048);
  arp_hdr.op = arp_op;
  arp_hdr.hlen = 6;
  arp_hdr.plen = 4;
  memcpy (arp_hdr.sha, new_eth_header->ether_shost, 6);
  memcpy (arp_hdr.tha, new_eth_header->ether_dhost, 6);
  arp_hdr.spa = s_ddr;
  arp_hdr.tpa = d_ddr;
  /* Se formeaza noul pachet */
  memcpy (packet.payload, new_eth_header, sizeof (struct ether_header));
  memcpy (packet.payload + sizeof (struct ether_header), &arp_hdr,
	  sizeof (struct arp_header));
  packet.len = sizeof (struct arp_header) + sizeof (struct ether_header);
  packet.interface = interface;
  send_packet (&packet);
}

/* Un comparator folosit la sortarea tabelei de dirijare */
bool comparator_route_table (const struct route_table_entry &a,
			const struct route_table_entry &b)
{
  if (a.prefix == b.prefix)
    {
      return a.mask < b.mask;
    }
  else
    return a.prefix < b.prefix;

}

/* Implementarea LPM folosind cautarea binara */
route_table_entry * route_table_best_route (uint32_t dest_ip, struct route_table * route_table)
{
  int result = 0;
  int left = 0, right = route_table->length - 1;
  struct route_table_entry *final_result = NULL;
  while (left <= right)
    {
      int mid = (left + right) / 2;
      if (route_table->entry[mid].prefix ==
	  (dest_ip & route_table->entry[mid].mask))
	{
	  result = mid;
	  left = mid + 1;
	}
      if (route_table->entry[mid].prefix <
	  (dest_ip & route_table->entry[mid].mask))
	{
	  left = mid + 1;
	}
      else
	{
	  right = mid - 1;
	}
    }
  for (int i = result; i < route_table->length; i++)
    {
      if (route_table->entry[i].prefix ==
	  (dest_ip & route_table->entry[i].mask))
	if (final_result == NULL
	    || (final_result->mask < route_table->entry[i].mask))
	  final_result = &route_table->entry[i];
    }
  return final_result;
}

/* Functie care initializeaza o tabela de dirijare*/
route_table * init_route_table (const char *path)
{
  route_table *route_table =
    (struct route_table *) malloc (sizeof (struct route_table));
  FILE *file = fopen (path, "r");
  int size = 0;
  char ch = fgetc (file);
  while (ch != EOF)
    {
      if (ch == '\n')
	size++;
      ch = getc (file);
    }
  route_table->length = size;
  fclose (file);
  route_table->entry =
    (struct route_table_entry *) malloc (size *
					 sizeof (struct route_table_entry));
  read_rtable (path, route_table->entry);
  sort (route_table->entry, route_table->entry + size,
	comparator_route_table);
  return route_table;
}

/* Functie care implementeaza ecuatia 4 din RFC 1624
   Noua suma de control se foloseste de vechea suma */
uint16_t ip_checksum_bonus (uint16_t old_checksum, uint16_t old_field_value,
		   uint16_t new_field_value)
{
  return old_checksum - ~(old_field_value) - new_field_value;
}

int main (int argc, char *argv[])
{
  setvbuf (stdout, NULL, _IONBF, 0);
  init (argc - 2, argv + 2);
  /*Structurile necesare pentru implementarea tuturor cerintelor */
  queue < packet > queue_packet_arp;
  route_table *route_table = init_route_table (argv[1]);
  arp_table *arp_table =
    (struct arp_table *) malloc (sizeof (struct arp_table));
  arp_table->entry =
    (struct arp_entry *) malloc (ETH_ALEN * sizeof (struct arp_entry));
  arp_table->length = 0;
  while (1)
    {
      packet m;
      int rc = get_packet (&m);
      DIE (rc < 0, "get_message");
      /*Se proceseaza toate antetele */
      struct ether_header *ether_header = (struct ether_header *) m.payload;
      struct icmphdr *icmp_header = get_icmp_header (m.payload);
      struct arp_header *arp_header = get_arp_header (m.payload);
      struct iphdr *ip_header =
	(struct iphdr *) (m.payload + sizeof (struct ether_header));
      uint8_t mac_addr[ETH_ALEN];
      const char *ip = get_interface_ip (m.interface);
      struct in_addr inp;
      get_interface_mac (m.interface, mac_addr);
      inet_aton (ip, &inp);
      /*Cazul in care pachetul este ARP */
      if (arp_header)
	{
	  if (arp_header->op == htons (ARPOP_REQUEST))
	    {
	      arp_entry *elem = get_arp_entry (arp_header->spa, arp_table);
	      if (!elem)
		{
		  arp_entry entry
		  {
		  };
		  entry.ip = arp_header->spa;
		  memcpy (entry.mac, arp_header->sha, ETH_ALEN);
		  add_entry_arp (arp_table, entry);
		}
	      struct ether_header aux_ether_header
	      {
	      };
	      aux_ether_header.ether_type = htons (ETHERTYPE_ARP);
	      memcpy (aux_ether_header.ether_dhost, ether_header->ether_shost,
		      ETH_ALEN);
	      get_interface_mac (m.interface, aux_ether_header.ether_shost);
	      /*Se trimite un pachet ARP */
	      send_arp_p (arp_header->spa, arp_header->tpa, &aux_ether_header,
			  m.interface, htons (ARPOP_REPLY));
	    }
	  else if (arp_header->op == htons (ARPOP_REPLY))
	    {
	      arp_entry *elem_aux =
		get_arp_entry (arp_header->spa, arp_table);
	      if (elem_aux)
		continue;
	      arp_entry elem;
	      elem.ip = arp_header->spa;
	      memcpy (elem.mac, ether_header->ether_shost, ETH_ALEN);
	      add_entry_arp (arp_table, elem);
	      queue < packet > aux_queue;
	      /*Se trimit pachetele din coada */
	      while (!queue_packet_arp.empty ())
		{
		  packet p = queue_packet_arp.front ();
		  queue_packet_arp.pop ();
		  struct iphdr *aux_ipd =
		    (struct iphdr *) (p.payload +
				      sizeof (struct ether_header));
		  route_table_entry *result_route =
		    route_table_best_route (aux_ipd->daddr, route_table);
		  if (result_route
		      && result_route->next_hop == arp_header->spa)
		    {
		      struct ether_header *aux_eth =
			(struct ether_header *) p.payload;
		      memcpy (aux_eth->ether_dhost, elem.mac, ETH_ALEN);
		      memcpy (aux_eth->ether_shost, mac_addr, ETH_ALEN);
		      p.interface = result_route->interface;
		      send_packet (&p);
		    }
		  else
		    {
		      aux_queue.push (p);
		    }
		}
	      queue_packet_arp.swap (aux_queue);
	    }
	  continue;
	}
      /*Cazul in care pachetul este Ipv4
         Aici este implementat procesul de dirijare */
      if (ether_header->ether_type == htons (ETHERTYPE_IP))
	{
	  /*Cazul in care pachetul este ICMP */
	  if (icmp_header && inp.s_addr == ip_header->daddr
	      && icmp_header->type == ICMP_ECHO)
	    {
	      uint16_t check_sum = icmp_header->checksum;
	      icmp_header->checksum = 0;
	      if (check_sum !=
		  icmp_checksum ((uint16_t *) icmp_header,
				 sizeof (struct icmphdr)))
		{
		  continue;
		}
	      /*Se trimite un pachet ICMP */
	      send_icmp_p (ip_header->saddr, ip_header->daddr,
			   ether_header->ether_dhost,
			   ether_header->ether_shost, 0, 0, m.interface, 0,
			   0);
	      continue;
	    }
	  /*Cazul in care pachetul este expirat */
	  if (ip_header->ttl <= 1)
	    {
	      send_icmp_p (ip_header->saddr, ip_header->daddr,
			   ether_header->ether_dhost,
			   ether_header->ether_shost, ICMP_TIME_EXCEEDED,
			   ICMP_EXC_TTL, m.interface, 0, 0);
	      continue;
	    }
	  uint16_t checksum_ip = ip_header->check;
	  ip_header->check = 0;
	  /*Cazul in care suma de control este gresita */
	  if (checksum_ip != ip_checksum (ip_header, sizeof (struct iphdr)))
	    continue;
	  /*Se decrementeaza TTL-ul */
	  ip_header->ttl--;
	  /*Se foloseste functia bonus pentru a obtine noua suma de control */
	  ip_header->check =
	    ip_checksum_bonus (checksum_ip, ip_header->ttl, ip_header->ttl);
	  route_table_entry *result_route =
	    route_table_best_route (ip_header->daddr, route_table);
	  /*Cazul in care host-ul este necunoscut (se raspunde cu ICMP host-unreachable) */
	  if (!result_route)
	    {
	      send_icmp_p (ip_header->saddr, ip_header->daddr,
			   ether_header->ether_dhost,
			   ether_header->ether_shost, ICMP_DEST_UNREACH,
			   ICMP_NET_UNREACH, m.interface, 0, 0);
	      continue;
	    }
	  /*Daca exista o intrare in tabela ARP */
	  arp_entry *elem = get_arp_entry (result_route->next_hop, arp_table);
	  if (elem)
	    {
	      memcpy (ether_header->ether_dhost, elem->mac, ETH_ALEN);
	      get_interface_mac (result_route->interface,
				 ether_header->ether_shost);
	      m.interface = result_route->interface;
	      /*Se trimite pachetul */
	      send_packet (&m);
	    }
	  else
	    {
	      /*Se pune in coada */
	      queue_packet_arp.push (m);
	      struct ether_header aux_ether_header
	      {
	      };
	      aux_ether_header.ether_type = htons (ETHERTYPE_ARP);
	      get_interface_mac (result_route->interface,
				 aux_ether_header.ether_shost);
	      hwaddr_aton ("FF:FF:FF:FF:FF:FF", aux_ether_header.ether_dhost);
	      const char *ip_broadcast =
		get_interface_ip (result_route->interface);
	      struct in_addr ip_p_br;
	      inet_aton (ip_broadcast, &ip_p_br);
	      /*Se trimite un pachet ARP */
	      send_arp_p (result_route->next_hop, ip_p_br.s_addr,
			  &aux_ether_header, result_route->interface,
			  htons (ARPOP_REQUEST));
	    }
	}
    }
  free (route_table->entry);
  free (route_table);
  free (arp_table->entry);
  free (arp_table);
  return 0;
}
